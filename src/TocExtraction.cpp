/* Copyright 2026 the SumatraPDF project authors (see AUTHORS file).
   License: GPLv3 */

#include "utils/BaseUtil.h"
#include "utils/WinUtil.h"
#include "utils/Dpi.h"
#include "utils/UITask.h"
#include "wingui/UIModels.h"
#include "wingui/Layout.h"
#include "wingui/WinGui.h"
#include "Settings.h"
#include "DisplayMode.h"
#include "DocController.h"
#include "EngineBase.h"
#include "DisplayModel.h"
#include "SumatraPDF.h"
#include "MainWindow.h"
#include "ExtractPdfToc.h"
#include "TocCalib.h"
#include "TocExtraction.h"
#include "Notifications.h"
#include "SumatraDialogs.h"
#include "AppDialogTheme.h"
#include "resource.h"
#include "Theme.h"
#include "Translations.h"
#include "DarkModeSubclass.h"

void EngineMupdfEnsurePageLinksForHitTest(EngineBase* engine, int pageNo);
bool EngineMupdfCanEditPdfToc(EngineBase* engine);
bool EngineMupdfCanExtractToc(EngineBase* engine);

void ShowTocExtraction(MainWindow* win) {
    DisplayModel* dm = win ? win->AsFixed() : nullptr;
    EngineBase* engine = dm ? dm->GetEngine() : nullptr;
    if (!engine || !EngineMupdfCanExtractToc(engine)) {
        return;
    }
    if (TocCalibIsActive(win)) {
        ShowTocCalib(win);
        return;
    }
    if (ExtractPdfTocIsRunning()) {
        return;
    }
    HandleExtractPdfTocCommand(win);
}

int ApplyTocLinkEvidence(EngineBase* engine, Vec<ExtractedTocItem*>& roots) {
    if (!engine) {
        return 0;
    }
    Vec<ExtractedTocItem*> flat;
    FlattenExtractedTocItems(roots, flat);
    int matched = 0;
    for (ExtractedTocItem* it : flat) {
        if (it->tocPageNo < 1 || it->tocPageNo > engine->PageCount() || (it->tocX == 0 && it->tocY == 0)) {
            continue;
        }
        EngineMupdfEnsurePageLinksForHitTest(engine, it->tocPageNo);
        Vec<IPageElement*> elements = engine->GetElements(it->tocPageNo);
        IPageDestination* found = nullptr;
        bool ambiguous = false;
        for (IPageElement* el : elements) {
            IPageDestination* dest = el && el->IsLink() ? el->AsLink() : nullptr;
            if (!dest || dest->pageNo < 1 || dest->pageNo > engine->PageCount()) {
                continue;
            }
            RectF r = el->GetRect();
            if (it->tocX < r.x - 3 || it->tocX > r.x + r.dx + 3 || it->tocY < r.y - 3 || it->tocY > r.y + r.dy + 3) {
                continue;
            }
            if (found &&
                (found->pageNo != dest->pageNo || found->rect.x != dest->rect.x || found->rect.y != dest->rect.y)) {
                ambiguous = true;
            }
            found = dest;
        }
        if (!found || ambiguous) {
            continue;
        }
        it->pageNo = found->pageNo;
        it->x = (float)found->rect.x;
        it->y = (float)found->rect.y;
        it->destinationSource = TocDestinationSource::PdfLink;
        it->verified = true;
        it->confidence = 100;
        matched++;
    }
    return matched;
}

void PrepareTocExtractionResult(EngineBase* engine, Vec<ExtractedTocItem*>& roots) {
    ApplyTocLinkEvidence(engine, roots);
    Vec<ExtractedTocItem*> flat;
    FlattenExtractedTocItems(roots, flat);
    for (ExtractedTocItem* it : flat) {
        if (it->pageNo < 1 || it->pageNo > engine->PageCount()) {
            it->pageNo = 0;
            it->destinationSource = TocDestinationSource::Unknown;
            it->verified = it->bodyMatched = false;
        } else if (it->destinationSource == TocDestinationSource::Unknown) {
            it->destinationSource = it->bodyMatched || it->source == ExtractedTocSource::BodyInference
                                        ? TocDestinationSource::BodyMatch
                                        : TocDestinationSource::Estimated;
        }
        if (it->destinationSource == TocDestinationSource::Estimated) {
            it->verified = false;
            it->confidence = std::min(it->confidence, 60);
        }
    }
}

bool PreviewTocExtraction(MainWindow* win, EngineBase* engine, Vec<ExtractedTocItem*>& roots, bool persistToDisk,
                          HWND parent) {
    (void)parent;
    if (!win || !engine) {
        return false;
    }
    PrepareTocExtractionResult(engine, roots);
    return StartTocCalib(win, roots, engine, persistToDisk, true);
}

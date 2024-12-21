import LeaderLine from "leader-line-new";
import { Reachability } from "../../controllers/reachability";

import "./navigation.css";

export class Navigation {
    lines: Map<Node, Map<Node, LeaderLine>> = new Map();

    constructor(private reachability: Reachability) { }

    createLine(from: Node, to: Node) {
        const line = new LeaderLine(from, to, {
            outline: true,
            color: 'transparent',
            endPlugOutline: true,
            hide: true
        });
        line.show('draw');
        return line;
    }

    addLine(from: Node, to: Node) {
        if(this.lines.has(from)) {
            let fromMap = this.lines.get(from);
            if (!fromMap!.has(to)) {
                fromMap!.set(to, this.createLine(from, to));
            }
        } else {
            let fromMap = new Map();
            fromMap.set(to, this.createLine(from, to));
            this.lines.set(from, fromMap);
        }
    }

    updateLinesPositions() {
        [...this.lines.values()].flatMap(
            fromMap => [...fromMap.values()]
        ).forEach(line => {
            if (
                (line.start as any).checkVisibility() &&
                (line.end as any).checkVisibility()
            ) {
                line.position();
                line.show();
            } else {
                line.hide();
            }
        });
    }

    initNavigation() {
        let element = document.documentElement;
        let initialPosition = { top: 0, left: 0, x: 0, y: 0 };
        let lastPosition = {x: 0, y: 0};
        let panPosition = {x: 0, y: 0, scrollLeft: 0, scrollTop: 0};
        let panScale = 1;

        const stopSelection = (e: Event) => {
            e.preventDefault();
        };

        const maybeStopDraggingCtrlKey = (e: KeyboardEvent) => {
            if (!e.ctrlKey) { stopDragging(e); }
        };

        const startDragging = (e: MouseEvent) => {
            if (e.ctrlKey) {
                initialPosition.left = element.scrollLeft;
                initialPosition.top = element.scrollTop;
                initialPosition.x = e.clientX;
                initialPosition.y = e.clientY;
                element.addEventListener('mousemove', whileDragging, {passive: true});
                element.addEventListener('mouseup', stopDragging);
                element.addEventListener('mouseleave', stopDragging);
                element.addEventListener('dragend', stopDragging);
                element.addEventListener('keyup', maybeStopDraggingCtrlKey);
                element.addEventListener('selectstart', stopSelection);
            }
        };

        const whileDragging = (e: MouseEvent) => {
            if (e.ctrlKey) {
                const deltaX = e.clientX - initialPosition.x;
                const deltaY = e.clientY - initialPosition.y;
                element.scrollLeft = initialPosition.left - deltaX;
                element.scrollTop = initialPosition.top - deltaY;
            } else {
                stopDragging(e);
            }
        };

        const stopDragging = (e: Event) => {
            element.removeEventListener('mousemove', whileDragging);
            element.removeEventListener('mouseup', stopDragging);
            element.removeEventListener('mouseleave', stopDragging);
            element.removeEventListener('dragend', stopDragging);
            element.removeEventListener('keyup', maybeStopDraggingCtrlKey);
            element.removeEventListener('selectstart', stopSelection);
        };

        const stopClicks = (e: MouseEvent) => {
            e.preventDefault();
            e.stopImmediatePropagation();
            return false;
        };

        const whilePanning = (e: MouseEvent) => {
            lastPosition = {x: e.clientX, y: e.clientY};
        };

        const maybeStopPanningAltKey = (e: KeyboardEvent) => {
            if (!e.altKey) {
                stopPanning();
            }
        };

        const startPanning = (e: KeyboardEvent) => {
            if (e.altKey) {
                const widthProp = (screen.availWidth) / (element.scrollWidth + element.scrollLeft + lastPosition.x);
                const heightProp = (screen.availHeight) / (element.scrollHeight + element.scrollTop + lastPosition.y);
                panScale = Math.min(1, widthProp, heightProp);
                panPosition = {...lastPosition, scrollLeft: element.scrollLeft, scrollTop: element.scrollTop};
                console.log('panPosition', panPosition);

                element.style.setProperty(
                    '--navigation-panning-scale',
                    String(panScale)
                );
                element.style.setProperty(
                    '--navigation-panning-x',
                    String(element.scrollLeft + lastPosition.x) + "px"
                );
                element.style.setProperty(
                    '--navigation-panning-y',
                    String(element.scrollTop + lastPosition.y) + "px"
                );
                element.classList.add('navigation-panning');
                element.addEventListener('keyup', maybeStopPanningAltKey);
                element.addEventListener('click', stopClicks, {capture: true});
                addEventListener('blur', stopPanning);
                element.removeEventListener('keydown', startPanning);
            }
        };

        const stopPanning = () => {
            const leftDelta = panPosition.scrollLeft - element.scrollLeft;
            const topDelta = panPosition.scrollTop - element.scrollTop;
            const xDelta = lastPosition.x - panPosition.x;
            const yDelta = lastPosition.y - panPosition.y;
            element.classList.remove('navigation-panning');
            element.scrollBy({
                left: (xDelta - leftDelta) / panScale - (xDelta  - leftDelta),
                top: (yDelta - topDelta) / panScale - (yDelta  - topDelta),
            });
            element.removeEventListener('keyup', maybeStopPanningAltKey);
            element.removeEventListener('click', stopClicks, {capture: true});
            removeEventListener('blur', stopPanning);
            element.addEventListener('keydown', startPanning);
        };

        element.addEventListener('mousedown', startDragging);
        element.addEventListener('mousemove', whilePanning, {passive: true});
        element.addEventListener('keydown', startPanning);
    }
}
import { interpolateHtml } from "../html";
import threeHtml from "./three.html";

import "./three.css";

type ThreeViewEvent = 'expand' | 'expandAll' | 'collapse' | 'collapseAll' | 'select';
type ThreeViewSide = 'left' | 'right';
type ThreeViewEventHandler<T> = (e: { target: Event; data: ThreeViewItem<T>; }) => void;

export type ThreeViewItem<T> = {
    name: string;
    label?: string;
    expanded?: boolean; // defaults to true
    selected?: boolean; // defaults to false
    side?: ThreeViewSide; // defaults to right
    children?: ThreeViewItem<T>[];
    data?: T;
};

class ThreeView<T> {
    static INPUT_TIME_THRESHOLD = 1e3;

    static getNodeFragment(name: string, label: string, data: string) {
        return interpolateHtml(threeHtml, new Map([
            [`//*[@class="three-node"]/@data-item`, data],
            [`//*[@class="three-node"]/@data-label`, label],
            [`//*[@class="three-label"]/text()`, name]
        ]));
    }

    constructor(children: ThreeViewItem<T>[] | undefined, private parentNode: HTMLElement, private topThree: ThreeView<T>|null =null) {
        if (!this.topThree) this.topThree = this;
        if (children) {
            for(let item of children) {
                const childNodeFragment = ThreeView.getNodeFragment(
                    item.name,
                    item.label || item.name,
                    JSON.stringify(item)
                );
                const childNode = childNodeFragment.querySelector('.three-node') as HTMLElement;
                if (item.expanded != false && item.children?.length) {
                    this.expand(childNode);
                } else {
                    this.collapse(childNode);
                }
                if (item.selected == true) {
                    this.select(childNode);
                }
                this.listenToEvents(childNode);
                new ThreeView(
                    item.children?.filter(item => item.side == 'left'),
                    childNodeFragment.querySelector('.three-left') as HTMLElement,
                    this.topThree
                );
                new ThreeView(
                    item.children?.filter(item => item.side != 'left'),
                    childNodeFragment.querySelector('.three-right') as HTMLElement,
                    this.topThree
                );
                parentNode.appendChild(childNodeFragment);
            }
        }
    }

    listenToEvents(node: HTMLElement) {
        node.addEventListener('click', e => {
            const element = e.target as HTMLElement|null;
            if (element?.closest('.three-node') == node) {
                this.focus(node);
            }
        });
        node.addEventListener('keydown', e => {
            if (e.target == node) {
                let tree = this.getTopThreeContainer();
                let currentTime = performance.now();
                let lastEvent = parseInt(tree?.dataset.lastEvent || "0");
                let prefix = tree?.dataset.prefix || "";
                if (currentTime - lastEvent > ThreeView.INPUT_TIME_THRESHOLD) {
                    prefix = "";
                }
                let newPrefix = "";
                let nextChild = node.querySelector('.three-node') as HTMLElement|null;
                let prevNode = node.parentElement!.closest('.three-node') as HTMLElement|null;
                switch (e.key) {
                    case "ArrowRight":
                        if (node.ariaExpanded == "false") {
                            if (nextChild) {
                                this.expand(node);
                            }
                        } else {
                            if (nextChild) {
                                this.focus(nextChild!);
                            }
                        }
                        break;
                    case "ArrowLeft":
                        if (node.ariaExpanded == "true") {
                            this.collapse(node);
                        } else {
                            if (prevNode) {
                                this.focus(prevNode);
                            }
                        }
                        break;
                    case "ArrowDown":
                        if (nextChild && (nextChild as any).checkVisibility()) {
                            this.focus(nextChild);
                        } else {
                            let tmpNode: HTMLElement|null = node;
                            while (tmpNode && !tmpNode.nextElementSibling) {
                                tmpNode = tmpNode.parentElement!.closest('.three-node');
                            }
                            if (tmpNode) {
                                this.focus(tmpNode.nextElementSibling as HTMLElement);
                            }
                        }
                        break;
                    case "ArrowUp":
                        if (node.previousElementSibling) {
                            let lastVisibleChild = this.getPreviousVisible(node.previousElementSibling as HTMLElement);
                            if (lastVisibleChild) {
                                this.focus(lastVisibleChild as HTMLElement);
                            } else {
                                this.focus(node.previousElementSibling as HTMLElement);
                            }
                        } else if (prevNode) {
                            this.focus(prevNode);
                        }
                        break;
                    case "Home":
                        const firstTreeChild = this.getFirst();
                        if (firstTreeChild) {
                            this.focus(firstTreeChild as HTMLElement);
                        }
                        break;
                    case "End":
                        if (tree?.lastElementChild) {
                            let lastVisibleChild = this.getPreviousVisible(tree.lastElementChild as HTMLElement);
                            if (lastVisibleChild) {
                                this.focus(lastVisibleChild as HTMLElement);
                            } else {
                                this.focus(tree.lastElementChild as HTMLElement);
                            }
                        }
                        break;
                    case "Alt":
                    case "Shift":
                    case "Ctrl":
                        newPrefix = prefix;
                        lastEvent = currentTime;
                        break;
                    default:
                        if (tree && [...e.key].length == 1) {
                            newPrefix = prefix + e.key;
                            let newNode = tree.querySelector(`.three-node[data-label^="${CSS.escape(newPrefix)}"]`);
                            if (newNode) {
                                tree.dataset.lastEvent = String(currentTime);
                                this.focus(newNode as HTMLElement);
                            }
                        }
                }
                if (tree) {
                    tree.dataset.prefix = newPrefix;
                }
                switch(e.key) {
                    case "ArrowUp":
                    case "ArrowDown":
                    case "ArrowLeft":
                    case "ArrowRight":
                        if (!e.altKey) e.preventDefault();
                        break;
                }
            }
        });
    }

    getTopThreeContainer() {
        return this.topThree?.parentNode;
    }

    getFirst() {
        return this.getTopThreeContainer()?.querySelector('.three-node') as HTMLElement;
    }

    getPreviousVisible(node: HTMLElement) {
        return [...node.querySelectorAll('.three-node')].reverse().find(
            (c: any) => c.checkVisibility());
    }

    getSelected() {
        return this.getTopThreeContainer()?.querySelectorAll('[aria-selected="true"]') as NodeListOf<HTMLElement>;
    }

    select(node: HTMLElement) {
        let from = this.getSelected();
        node.setAttribute('aria-selected', 'true');
        from?.forEach(elem => elem != node && elem.removeAttribute('aria-selected'));
        this.focus(node);
    }

    getFocusable() {
        return this.getTopThreeContainer()?.querySelectorAll('[tabindex]');
    }

    focus(to: HTMLElement) {
        let from = this.getFocusable();
        to.setAttribute('tabindex', '0');
        to.focus();
        from?.forEach(elem => elem != to && elem.removeAttribute('tabindex'));
    }

    expand(node: HTMLElement) {
        node.ariaExpanded = "true";
    }

    collapse(node: HTMLElement) {
        node.ariaExpanded = "false";
    }

    private eventHandlers: Map<ThreeViewEvent, WeakMap<ThreeViewEventHandler<T>, AbortController>> = new Map;
    on(
        event: ThreeViewEvent,
        handler: ThreeViewEventHandler<T>
    ): void {
        const map = this.eventHandlers.get(event) ?? new WeakMap<ThreeViewEventHandler<T>, AbortController>;
        if (event == "select") {
            const aborter = new AbortController();
            let handleSelectEvent = (element: HTMLElement, e: Event) => {
                const node = element.closest('.three-node') as HTMLElement;
                this.select(node);
                handler({
                    target: e,
                    data: JSON.parse(node.dataset.item!)
                });
            };
            this.parentNode.addEventListener('click', (e: Event) => {
                handleSelectEvent(e.target as HTMLElement, e);
            }, { signal: aborter.signal });
            this.parentNode.addEventListener('keydown', (e: KeyboardEvent) => {
                if (e.key != "Enter") return;
                handleSelectEvent(e.target as HTMLElement, e);
            }, { signal: aborter.signal });
            map.set(handler, aborter);
        }
    }

    off(e: ThreeViewEvent, handler: ThreeViewEventHandler<T>): void {
        this.eventHandlers.get(e)?.get(handler)?.abort();
    }
}

export default ThreeView;
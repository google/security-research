declare module '*.html' {
    const value: string;
    export default value
}

declare module '*.sql' {
    const value: string;
    export default value
}

declare module 'js-treeview' {
    export type TreeViewItem<T> = {
        name: string;
        expanded?: boolean;
        children: item[];
        data?: T;
    };
    type TreeViewEvent = 'expand'|'expandAll'|'collapse'|'collapseAll'|'select';
    class TreeView<T> {
        constructor(data: TreeViewItem<T>[], node: DOMElement);
        on(
            event: TreeViewEvent,
            handler: function({target: UIEvent, data: TreeViewItem<T>})
        );
        off(event: TreeViewEvent, handler: Function);
    }
    export default TreeView;
}
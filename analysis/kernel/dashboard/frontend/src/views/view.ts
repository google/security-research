export class View {
    static async getRootNode(rootNode: HTMLDivElement | null, rootClassName: string): Promise<HTMLDivElement> {
        if (!rootNode) {
            rootNode = document.createElement('div');
            rootNode.className = rootClassName;
            if (document.readyState != "complete") {
                return new Promise(res => {
                    document.onreadystatechange = (e) => {
                        res(View.getRootNode(rootNode, rootClassName));
                    };
                });
            }
        }
        if (rootNode.parentNode == null) {
            let placeholder = document.getElementsByClassName(rootClassName)[0];
            if (!placeholder) {
                throw new Error('Could not initialize view, ' + rootClassName + ' missing.');
            }
            placeholder.parentNode?.replaceChild(rootNode, placeholder);
        }
        return rootNode;
    }
}
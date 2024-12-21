export function interpolateHtml(html: string, rules: Map<string, string>) {
    let fragment = document.createDocumentFragment();
    let doc = new DOMParser().parseFromString(html, "text/html");
    let changes: { next: Node; value: string; }[] = [];
    rules.forEach((value, xpath) => {
        let results = document.evaluate(xpath, doc, null, XPathResult.ANY_TYPE, null);
        for (let next = results.iterateNext(); next; next = results.iterateNext()) {
            changes.push({next, value});
        }
    });
    changes.forEach(({next, value}) => next.nodeValue = value);
    [...doc.body.childNodes].forEach(node => fragment.appendChild(node));
    return fragment;
};
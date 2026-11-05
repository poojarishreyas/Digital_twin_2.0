"""Build an IEEE-conference-style .docx from fidelity-cores.tex.

Steps: simplify LaTeX constructs that pandoc drops (multirow, figure*, TikZ,
thebibliography), resolve citations and cross-references to IEEE numbering,
convert with pandoc, then apply the IEEE layout with python-docx: US Letter,
single-column title block, two-column body, Times New Roman 10 pt, Roman
section numbers in small caps, TABLE captions above tables, Fig. captions
below figures, 8 pt references.

Run from the paper/ directory:  python3 build_docx.py
"""
import copy
import re
import subprocess
import tempfile
from pathlib import Path

import docx
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt

HERE = Path(__file__).resolve().parent
SRC = HERE / "fidelity-cores.tex"
OUT = HERE / "fidelity-cores.docx"
ROMAN = ["I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X"]
FONT = "Times New Roman"


def prepare(tex: str) -> str:
    a = tex.index(r"\begin{tikzpicture}")
    b = tex.index(r"\end{tikzpicture}") + len(r"\end{tikzpicture}")
    tex = tex[:a] + r"\includegraphics[width=\columnwidth]{figs/fig-loop.png}" + tex[b:]
    tex = tex.replace(r"\begin{figure*}[t]", r"\begin{figure}[t]").replace(r"\end{figure*}", r"\end{figure}")
    tex = tex.replace(r"\includegraphics[width=\textwidth]{figs/fig-fidelity-curve.png}",
                      r"\includegraphics[width=\columnwidth]{figs/fig-fidelity-curve-stacked.png}")

    def plain_math(block):
        subs = [(r"$G_{\text{core}}\cup G_{\text{pivot}}$", "G\\textsubscript{core} ∪ G\\textsubscript{pivot}"),
                (r"$G_{\text{core}}$", "G\\textsubscript{core}"), (r"$G_{\text{pivot}}$", "G\\textsubscript{pivot}"),
                (r"$G_{\text{expert}}$", "G\\textsubscript{expert}"), (r"$\varphi$", "φ"),
                (r"$|K|{=}0$", "|K| = 0"), (r"$K$", "K"), (r"$\Vb$", "V"), (r"$\Pb$", "P"),
                (r"$q=0.3$", "q = 0.3"), (r"$k=2$", "k = 2"), (r"$k=4$", "k = 4"), (r"$k=8$", "k = 8"),
                (r"$\times$", "×"), (r"Mean $|K|$", "Mean |K|")]
        for a, b in subs:
            block = block.replace(a, b)
        return block
    tex = re.sub(r"\\begin\{table\}.*?\\end\{table\}", lambda m: plain_math(m.group(0)), tex, flags=re.S)
    tex = re.sub(r"\\multirow\{2\}\{\*\}\{([^}]*)\}", r"\1", tex)
    tex = tex.replace("Nginx /admin/ open & & & 31 & \\\\", "Nginx /admin/ open & 6 / 12 & 10.4 (6--15) & 31 & 0.03\\\\")
    tex = tex.replace(r"""& \multicolumn{3}{c}{Naive} & \multicolumn{3}{c}{Careful}\\
\cmidrule(lr){2-4}\cmidrule(lr){5-7}
$\varphi$ & Acc. & FP & FN & Acc. & FP & FN\\""",
                      r"$\varphi$ & Naive acc. & FP & FN & Careful acc. & FP & FN\\")
    tex = re.sub(r"\\multicolumn\{\d+\}\{@\{\}p\{[0-9.]+\\columnwidth\}@\{\}\}\{\\footnotesize (.*?)\}\n\\end\{tabular\}",
                 lambda m: "\\end{tabular}\n\n\\emph{Note.} " + m.group(1) + "\n", tex, flags=re.S)
    tex = tex.replace("\\footnotesize\n\\begin{tabular}", "\\begin{tabular}")
    tex = tex.replace(r"""& \multicolumn{3}{c}{Naive} & \multicolumn{3}{c}{Careful}\\
\cmidrule(lr){2-4}\cmidrule(lr){5-7}
φ & Acc. & FP & FN & Acc. & FP & FN\\""", r"Property & Naive acc. & FP & FN & Careful acc. & FP & FN\\")
    tex = tex.replace(r"$\overline{|K|}$", r"Mean |K|")
    tex = tex.replace(r"\begin{IEEEkeywords}", r"KEYWORDSMARK ").replace(r"\end{IEEEkeywords}", "")
    keys = re.findall(r"\\bibitem\{([^}]+)\}", tex)
    num = {k: i + 1 for i, k in enumerate(keys)}
    tex = re.sub(r"~?\\cite\{([^}]+)\}", lambda m: "~" + ", ".join(f"[{num[k.strip()]}]" for k in m.group(1).split(",")), tex)
    a = tex.index(r"\begin{thebibliography}")
    b = tex.index(r"\end{thebibliography}") + len(r"\end{thebibliography}")
    items = re.split(r"\\bibitem\{[^}]+\}", tex[a:b])[1:]
    items[-1] = items[-1].replace(r"\end{thebibliography}", "")
    tex = tex[:a] + "\\section*{References}\n\n" + "\n\n".join(f"REFMARK[{i+1}] {t.strip()}" for i, t in enumerate(items)) + "\n" + tex[b:]
    labels = {"sec:concepts": "III", "sec:harness": "IV", "sec:results": "V", "sec:discussion": "VI",
              "sec:static": "V-E", "tab:corpus": "I", "tab:cores": "II", "tab:gsync": "III", "tab:resync": "IV",
              "tab:static": "V", "fig:loop": "1", "fig:curve": "2", "fig:cores": "3", "fig:resync": "4"}
    tex = re.sub(r"\\ref\{([^}]+)\}", lambda m: labels[m.group(1)], tex)
    return tex


def set_run_font(run, size=None, bold=None, italic=None, smallcaps=None, name=FONT):
    run.font.name = name
    rpr = run._element.get_or_add_rPr()
    fonts = rpr.find(qn("w:rFonts"))
    if fonts is None:
        fonts = OxmlElement("w:rFonts")
        rpr.insert(0, fonts)
    for att in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"):
        fonts.set(qn(att), name)
    if size:
        run.font.size = Pt(size)
    if bold is not None:
        run.font.bold = bold
    if italic is not None:
        run.font.italic = italic
    if smallcaps is not None:
        run.font.small_caps = smallcaps


def style_font(style, size, bold=False, italic=False, name=FONT):
    style.font.name = name
    style.font.size = Pt(size)
    style.font.bold = bold
    style.font.italic = italic
    style.font.color.rgb = None
    rpr = style.element.get_or_add_rPr()
    fonts = rpr.find(qn("w:rFonts"))
    if fonts is None:
        fonts = OxmlElement("w:rFonts")
        rpr.insert(0, fonts)
    for att in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"):
        fonts.set(qn(att), name)
    for att in ("w:asciiTheme", "w:hAnsiTheme", "w:cstheme", "w:eastAsiaTheme"):
        if fonts.get(qn(att)) is not None:
            del fonts.attrib[qn(att)]


def para_fmt(p, align=None, before=0, after=0, first=None, left=None, hanging=None, keep=False):
    f = p.paragraph_format
    if align is not None:
        f.alignment = align
    f.space_before = Pt(before)
    f.space_after = Pt(after)
    f.line_spacing = 1.0
    if first is not None:
        f.first_line_indent = Inches(first)
    if left is not None:
        f.left_indent = Inches(left)
    if hanging is not None:
        f.left_indent = Inches(hanging)
        f.first_line_indent = Inches(-hanging)
    if keep:
        f.keep_with_next = True


def insert_paragraph_after(par, text="", style=None):
    new_p = OxmlElement("w:p")
    par._p.addnext(new_p)
    np_ = docx.text.paragraph.Paragraph(new_p, par._parent)
    if style:
        np_.style = style
    if text:
        np_.add_run(text)
    return np_


def columns(sect_pr, num, space_twips=360):
    cols = sect_pr.find(qn("w:cols"))
    if cols is None:
        cols = OxmlElement("w:cols")
        sect_pr.append(cols)
    cols.set(qn("w:num"), str(num))
    cols.set(qn("w:space"), str(space_twips))


def page_setup(sect):
    sect.page_width, sect.page_height = Inches(8.5), Inches(11)
    sect.top_margin, sect.bottom_margin = Inches(0.75), Inches(1.0)
    sect.left_margin = sect.right_margin = Inches(0.625)


def main():
    tex = prepare(SRC.read_text())
    with tempfile.TemporaryDirectory() as tmp:
        t = Path(tmp) / "paper.tex"
        t.write_text(tex)
        raw = Path(tmp) / "raw.docx"
        subprocess.run(["pandoc", str(t), "-o", str(raw), "--resource-path", str(HERE)], check=True, cwd=HERE)
        d = docx.Document(raw)

    class _S:
        def __init__(self, styles):
            self.by = {x.name.lower(): x for x in styles}

        def __getitem__(self, k):
            return self.by[k.lower()]

        def __iter__(self):
            return iter(self.by.values())

    st = _S(d.styles)
    for name in ("Normal", "Body Text", "First Paragraph", "Compact"):
        style_font(st[name], 10)
        st[name].paragraph_format.space_before = Pt(0)
        st[name].paragraph_format.space_after = Pt(0)
    for name in ("Heading 1", "Heading 2", "Heading 3"):
        style_font(st[name], 10, italic=(name != "Heading 1"))
    style_font(st["Title"], 24)
    for name in ("Image Caption", "Table Caption", "Abstract"):
        style_font(st[name], 8 if name != "Abstract" else 9, bold=(name == "Abstract"))
    style_font(st["Verbatim Char"], 9, name="Courier New") if "Verbatim Char" in [s.name for s in st] else None

    paras = list(d.paragraphs)
    sec_no, sub_no, fig_no, tab_no = 0, 0, 0, 0
    title = next(p for p in paras if p.style.name == "Title")
    title.text = title.text.replace("\n", " ")
    for r in title.runs:
        set_run_font(r, 24)
    para_fmt(title, WD_ALIGN_PARAGRAPH.CENTER, 0, 12)
    # author block
    lines = [("Author Name(s)", 11, False), ("Department, Organization", 10, True), ("City, Country", 10, False),
             ("email@organization.org", 10, False)]
    last = title
    for text, size, it in lines:
        last = insert_paragraph_after(last, style=st["Author"])
        set_run_font(last.add_run(text), size, italic=it)
        para_fmt(last, WD_ALIGN_PARAGRAPH.CENTER, 0, 0)
    para_fmt(last, WD_ALIGN_PARAGRAPH.CENTER, 0, 14)
    # end single-column section after the author block
    brk = insert_paragraph_after(last)
    ppr = brk._p.get_or_add_pPr()
    sect_pr = copy.deepcopy(d.sections[-1]._sectPr)
    ppr.append(sect_pr)
    first = d.sections[0]
    page_setup(first)
    columns(first._sectPr, 1)
    body = d.sections[-1]
    page_setup(body)
    body.start_type = WD_SECTION.CONTINUOUS
    columns(body._sectPr, 2, 288)
    para_fmt(brk, None, 0, 0)

    first_body_after_heading = False
    for p in d.paragraphs:
        name = p.style.name
        text = p.text
        if name == "Abstract Title":
            p._p.getparent().remove(p._p)
            continue
        if name == "Abstract":
            r0 = p.runs[0]
            lead = p.insert_paragraph_before("")
            p_runs = p._p
            ab = p_runs.makeelement(qn("w:r"), {})
            new = docx.text.run.Run(ab, p)
            p._p.insert(1 if p._p.pPr is not None else 0, ab)
            new.text = "Abstract\u2014"
            set_run_font(new, 9, bold=True, italic=True)
            lead._p.getparent().remove(lead._p)
            for r in p.runs[1:]:
                set_run_font(r, 9, bold=True)
            para_fmt(p, WD_ALIGN_PARAGRAPH.JUSTIFY, 0, 6, first=0.14)
            continue
        if text.startswith("KEYWORDSMARK"):
            for r in p.runs:
                r.text = r.text.replace("KEYWORDSMARK ", "").replace("KEYWORDSMARK", "")
            ab = p._p.makeelement(qn("w:r"), {})
            p._p.insert(1 if p._p.pPr is not None else 0, ab)
            new = docx.text.run.Run(ab, p)
            new.text = "Index Terms\u2014"
            set_run_font(new, 9, bold=True, italic=True)
            for r in p.runs[1:]:
                set_run_font(r, 9, bold=True)
            para_fmt(p, WD_ALIGN_PARAGRAPH.JUSTIFY, 0, 8, first=0.14)
            continue
        if name == "Heading 1":
            if text.strip() == "References":
                label = "References"
            else:
                sec_no += 1
                sub_no = 0
                label = f"{ROMAN[sec_no - 1]}. {text.strip()}"
            for r in p.runs[1:]:
                r.text = ""
            if p.runs:
                p.runs[0].text = label
            else:
                p.add_run(label)
            for r in p.runs:
                set_run_font(r, 10, smallcaps=True, bold=False, italic=False)
            para_fmt(p, WD_ALIGN_PARAGRAPH.CENTER, 8, 4, keep=True)
            first_body_after_heading = True
            continue
        if name == "Heading 2":
            sub_no += 1
            label = f"{chr(64 + sub_no)}. "
            ab = p._p.makeelement(qn("w:r"), {})
            p._p.insert(1 if p._p.pPr is not None else 0, ab)
            new = docx.text.run.Run(ab, p)
            new.text = label
            for r in p.runs:
                set_run_font(r, 10, italic=True, bold=False)
            para_fmt(p, WD_ALIGN_PARAGRAPH.LEFT, 6, 3, keep=True)
            continue
        if name == "Table Caption":
            tab_no += 1
            for r in p.runs:
                set_run_font(r, 8, smallcaps=True)
            ab = p._p.makeelement(qn("w:r"), {})
            p._p.insert(1 if p._p.pPr is not None else 0, ab)
            new = docx.text.run.Run(ab, p)
            new.text = f"TABLE {ROMAN[tab_no - 1]}"
            set_run_font(new, 8, smallcaps=False)
            new.add_break()
            para_fmt(p, WD_ALIGN_PARAGRAPH.CENTER, 8, 4, keep=True)
            # caption text may include math (lost text); keep OMML elements as they are
            continue
        if name == "Image Caption":
            fig_no += 1
            ab = p._p.makeelement(qn("w:r"), {})
            p._p.insert(1 if p._p.pPr is not None else 0, ab)
            new = docx.text.run.Run(ab, p)
            new.text = f"Fig. {fig_no}. "
            for r in p.runs:
                set_run_font(r, 8)
            para_fmt(p, WD_ALIGN_PARAGRAPH.JUSTIFY, 2, 8)
            continue
        if name == "Captioned Figure":
            para_fmt(p, WD_ALIGN_PARAGRAPH.CENTER, 6, 0, keep=True)
            continue
        if text.startswith("REFMARK"):
            for r in p.runs:
                r.text = r.text.replace("REFMARK", "")
                set_run_font(r, 8)
            para_fmt(p, WD_ALIGN_PARAGRAPH.JUSTIFY, 0, 2, hanging=0.3)
            continue
        if text.startswith("Note.") or (p.runs and p.runs[0].text.startswith("Note.")):
            for r in p.runs:
                set_run_font(r, 8)
            para_fmt(p, WD_ALIGN_PARAGRAPH.JUSTIFY, 2, 6)
            continue
        if name in ("Body Text", "First Paragraph", "Normal", "Compact"):
            for r in p.runs:
                if r.style is not None and r.style.name == "Verbatim Char":
                    set_run_font(r, 9, name="Courier New")
                else:
                    set_run_font(r, 10)
            is_list = p._p.pPr is not None and p._p.pPr.numPr is not None
            para_fmt(p, WD_ALIGN_PARAGRAPH.JUSTIFY, 0, 0, first=None if is_list else 0.14)
            if is_list:
                p.paragraph_format.space_after = Pt(1)
            first_body_after_heading = False

    # images: column width
    for shp in d.inline_shapes:
        ratio = shp.height / shp.width
        shp.width = Inches(3.4)
        shp.height = int(Inches(3.4) * ratio)

    # tables: booktabs-like borders, 8 pt
    for t in d.tables:
        t.alignment = WD_TABLE_ALIGNMENT.CENTER
        tbl_pr = t._tbl.tblPr
        for old in tbl_pr.findall(qn("w:tblBorders")):
            tbl_pr.remove(old)
        borders = OxmlElement("w:tblBorders")
        for edge, sz in (("top", 8), ("bottom", 8)):
            el = OxmlElement(f"w:{edge}")
            el.set(qn("w:val"), "single")
            el.set(qn("w:sz"), str(sz))
            el.set(qn("w:space"), "0")
            el.set(qn("w:color"), "000000")
            borders.append(el)
        tbl_pr.append(borders)
        ncol = len(t.columns)
        tbl_pr_w = tbl_pr.find(qn("w:tblW"))
        if tbl_pr_w is None:
            tbl_pr_w = OxmlElement("w:tblW")
            tbl_pr.append(tbl_pr_w)
        tbl_pr_w.set(qn("w:type"), "dxa")
        tbl_pr_w.set(qn("w:w"), str(int(3.45 * 1440)))
        mar = OxmlElement("w:tblCellMar")
        for edge in ("left", "right"):
            e = OxmlElement(f"w:{edge}")
            e.set(qn("w:w"), "45")
            e.set(qn("w:type"), "dxa")
            mar.append(e)
        tbl_pr.append(mar)
        layout = OxmlElement("w:tblLayout")
        layout.set(qn("w:type"), "fixed")
        tbl_pr.append(layout)
        weights = []
        for ci in range(ncol):
            texts = [row.cells[ci].text for row in t.rows]
            body_len = max(len(x) for x in texts[1:]) if len(texts) > 1 else 4
            head_word = max((len(w) for w in texts[0].split()), default=3)
            weights.append(min(max(body_len, head_word, 6), 13) + 1.5)
        widths = [3.45 * w / sum(weights) for w in weights]
        grid = t._tbl.tblGrid
        for gc, w in zip(grid.findall(qn("w:gridCol")), widths):
            gc.set(qn("w:w"), str(int(w * 1440)))
        for row in t.rows:
            for cell, w in zip(row.cells, widths):
                cell.width = Inches(w)
        for ri, row in enumerate(t.rows):
            for cell in row.cells:
                if ri == 0:
                    tc_pr = cell._tc.get_or_add_tcPr()
                    b = OxmlElement("w:tcBorders")
                    bt = OxmlElement("w:bottom")
                    bt.set(qn("w:val"), "single")
                    bt.set(qn("w:sz"), "4")
                    bt.set(qn("w:color"), "000000")
                    b.append(bt)
                    tc_pr.append(b)
                for p in cell.paragraphs:
                    for r in p.runs:
                        set_run_font(r, 8, bold=False)
                    para_fmt(p, None, 0, 0)
                    p.paragraph_format.first_line_indent = Inches(0)

    d.core_properties.title = "Fidelity Cores: How Much Configuration Does a Security Service Twin Actually Need?"
    d.core_properties.author = "Author Name(s)"
    d.save(OUT)
    print("wrote", OUT)


if __name__ == "__main__":
    main()

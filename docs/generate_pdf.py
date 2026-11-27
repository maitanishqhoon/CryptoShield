"""
Pure Python PDF Generator for CryptoShield Architecture Guide.
Generates a valid, multi-page PDF-1.4 file with custom typography,
tables, headers, footers, and page numbers without external libraries.
"""

import os
import sys

class SimplePDF:
    def __init__(self, filename="CryptoShield_Guide.pdf", page_width=595.28, page_height=841.89):
        # A4: 595.28 x 841.89 pt
        self.filename = filename
        self.width = page_width
        self.height = page_height
        self.margin_left = 42.0
        self.margin_right = 42.0
        self.margin_top = 45.0
        self.margin_bottom = 45.0
        self.usable_width = self.width - self.margin_left - self.margin_right
        
        self.pages = []  # list of list of drawing commands
        self.current_page_commands = []
        self.y = self.height - self.margin_top
        
        # Fonts catalog: F1 = Helvetica, F2 = Helvetica-Bold, F3 = Courier, F4 = Helvetica-Oblique
        self.fonts = {
            "F1": "/Helvetica",
            "F2": "/Helvetica-Bold",
            "F3": "/Courier",
            "F4": "/Helvetica-Oblique",
            "F5": "/Courier-Bold"
        }
        self.start_new_page(is_first=True)

    def start_new_page(self, is_first=False):
        if not is_first:
            self.pages.append(self.current_page_commands)
            self.current_page_commands = []
        self.y = self.height - self.margin_top
        # Page header (for pages > 1)
        page_num = len(self.pages) + 1
        if page_num > 1:
            self.set_color(0.5, 0.5, 0.5)
            self.draw_text("CryptoShield — Architecture & Operational Guide (Phases 1-8)", 
                           self.margin_left, self.height - 28, font="F4", size=8)
            self.draw_line(self.margin_left, self.height - 32, self.width - self.margin_right, self.height - 32, width=0.5)

    def finish(self):
        if self.current_page_commands:
            self.pages.append(self.current_page_commands)
        
        # Add page footers now that total pages are known
        total_pages = len(self.pages)
        for idx, page_cmds in enumerate(self.pages):
            p_num = idx + 1
            footer_text = f"Page {p_num} of {total_pages}"
            footer_line = f"0.7 0.7 0.7 RG 0.5 w {self.margin_left} 32 m {self.width - self.margin_right} 32 l S\n"
            footer_txt = f"0.4 0.4 0.4 rg BT /F1 8 Tf {self.width - self.margin_right - 55} 22 Td ({footer_text}) Tj ET\n"
            conf_txt = f"0.4 0.4 0.4 rg BT /F4 8 Tf {self.margin_left} 22 Td (NFSU / CryptoShield Team Reference Document) Tj ET\n"
            page_cmds.append(footer_line)
            page_cmds.append(footer_txt)
            page_cmds.append(conf_txt)
        
        self.compile_pdf()

    def check_space(self, needed_height):
        if self.y - needed_height < self.margin_bottom:
            self.start_new_page()

    def escape_text(self, text):
        return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    def set_color(self, r, g, b, is_fill=True):
        cmd = f"{r:.3f} {g:.3f} {b:.3f} {'rg' if is_fill else 'RG'}\n"
        self.current_page_commands.append(cmd)

    def draw_text(self, text, x, y, font="F1", size=10):
        esc = self.escape_text(text)
        cmd = f"BT /{font} {size} Tf {x:.2f} {y:.2f} Td ({esc}) Tj ET\n"
        self.current_page_commands.append(cmd)

    def draw_line(self, x1, y1, x2, y2, width=1.0, r=0.7, g=0.7, b=0.7):
        cmd = f"{r:.3f} {g:.3f} {b:.3f} RG {width:.2f} w {x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S\n"
        self.current_page_commands.append(cmd)

    def draw_rect(self, x, y, w, h, fill_rgb=None, stroke_rgb=None, line_width=1.0):
        cmds = []
        if fill_rgb:
            cmds.append(f"{fill_rgb[0]:.3f} {fill_rgb[1]:.3f} {fill_rgb[2]:.3f} rg\n")
        if stroke_rgb:
            cmds.append(f"{stroke_rgb[0]:.3f} {stroke_rgb[1]:.3f} {stroke_rgb[2]:.3f} RG\n")
            cmds.append(f"{line_width:.2f} w\n")
        cmds.append(f"{x:.2f} {y:.2f} {w:.2f} {h:.2f} re ")
        if fill_rgb and stroke_rgb:
            cmds.append("B\n")
        elif fill_rgb:
            cmds.append("f\n")
        elif stroke_rgb:
            cmds.append("S\n")
        self.current_page_commands.extend(cmds)

    def wrap_text(self, text, max_width, font="F1", size=10):
        # Approximate char width for Helvetica: ~0.52 * size, Bold: ~0.56 * size, Courier: 0.6 * size
        char_width = 0.53 * size
        if font in ["F2", "F5"]:
            char_width = 0.58 * size
        elif font == "F3":
            char_width = 0.60 * size
            
        max_chars = max(10, int(max_width / char_width))
        words = text.split(" ")
        lines = []
        current_line = []
        current_len = 0
        
        for w in words:
            w_len = len(w)
            if current_len + w_len + (1 if current_line else 0) <= max_chars:
                current_line.append(w)
                current_len += w_len + (1 if current_line else 0)
            else:
                if current_line:
                    lines.append(" ".join(current_line))
                current_line = [w]
                current_len = w_len
        if current_line:
            lines.append(" ".join(current_line))
        return lines

    def add_title(self, title, subtitle=None):
        self.check_space(70)
        self.set_color(0.06, 0.09, 0.16)
        self.draw_text(title, self.margin_left, self.y - 20, font="F2", size=18)
        self.y -= 26
        if subtitle:
            self.set_color(0.01, 0.52, 0.78)
            self.draw_text(subtitle, self.margin_left, self.y - 10, font="F1", size=10)
            self.y -= 16
        self.draw_line(self.margin_left, self.y - 4, self.width - self.margin_right, self.y - 4, width=1.5, r=0.01, g=0.52, b=0.78)
        self.y -= 14

    def add_heading2(self, text):
        self.check_space(45)
        self.y -= 10
        self.set_color(0.01, 0.41, 0.63)
        self.draw_text(text, self.margin_left, self.y - 12, font="F2", size=13)
        self.y -= 16
        self.draw_line(self.margin_left, self.y - 2, self.width - self.margin_right, self.y - 2, width=0.75, r=0.85, g=0.88, b=0.92)
        self.y -= 10

    def add_heading3(self, text):
        self.check_space(35)
        self.y -= 6
        self.set_color(0.12, 0.16, 0.23)
        self.draw_text(text, self.margin_left, self.y - 10, font="F2", size=11)
        self.y -= 16

    def add_paragraph(self, text, font="F1", size=9.5, line_spacing=13, color=(0.12, 0.16, 0.23)):
        lines = self.wrap_text(text, self.usable_width, font=font, size=size)
        needed = len(lines) * line_spacing + 6
        self.check_space(needed)
        self.set_color(*color)
        for line in lines:
            self.draw_text(line, self.margin_left, self.y - size, font=font, size=size)
            self.y -= line_spacing
        self.y -= 4

    def add_bullet(self, bold_prefix, text, indent=14, font="F1", size=9.5, line_spacing=13):
        full_text = f"{bold_prefix} {text}" if bold_prefix else text
        lines = self.wrap_text(full_text, self.usable_width - indent, font=font, size=size)
        needed = len(lines) * line_spacing + 4
        self.check_space(needed)
        
        # draw bullet symbol
        self.set_color(0.01, 0.52, 0.78)
        self.draw_text(">", self.margin_left + 2, self.y - size, font="F2", size=size)
        
        self.set_color(0.12, 0.16, 0.23)
        for idx, line in enumerate(lines):
            self.draw_text(line, self.margin_left + indent, self.y - size, font=font, size=size)
            self.y -= line_spacing
        self.y -= 2

    def add_callout(self, title, text):
        lines = self.wrap_text(text, self.usable_width - 24, font="F1", size=9.0)
        box_height = 20 + len(lines) * 12 + 10
        self.check_space(box_height + 10)
        self.y -= 6
        top_y = self.y
        # background box
        self.draw_rect(self.margin_left, top_y - box_height, self.usable_width, box_height, 
                       fill_rgb=(0.95, 0.97, 0.99), stroke_rgb=(0.80, 0.86, 0.93), line_width=1.0)
        # left accent line
        self.draw_rect(self.margin_left, top_y - box_height, 4, box_height, fill_rgb=(0.01, 0.52, 0.78))
        
        # title
        self.set_color(0.01, 0.41, 0.63)
        self.draw_text(title, self.margin_left + 14, top_y - 14, font="F2", size=9.5)
        # text lines
        self.set_color(0.20, 0.25, 0.33)
        curr_y = top_y - 28
        for line in lines:
            self.draw_text(line, self.margin_left + 14, curr_y, font="F1", size=9.0)
            curr_y -= 12
        self.y -= box_height + 8

    def add_table(self, headers, rows, col_widths):
        # col_widths: list of proportions or pts. We normalize to self.usable_width
        total_w = sum(col_widths)
        widths = [w / total_w * self.usable_width for w in col_widths]
        
        # calculate row heights
        line_height = 11
        pad_top = 4
        pad_bottom = 5
        
        def calc_row_h(cells, is_header=False):
            max_lines = 1
            f = "F2" if is_header else "F1"
            sz = 8.5
            for i, c in enumerate(cells):
                w = widths[i] - 10
                lns = self.wrap_text(c, w, font=f, size=sz)
                max_lines = max(max_lines, len(lns))
            return max_lines * line_height + pad_top + pad_bottom

        header_h = calc_row_h(headers, is_header=True)
        self.check_space(header_h + 30)
        
        # Draw header
        top_y = self.y
        self.draw_rect(self.margin_left, top_y - header_h, self.usable_width, header_h,
                       fill_rgb=(0.06, 0.09, 0.16), stroke_rgb=(0.06, 0.09, 0.16))
        
        curr_x = self.margin_left
        for i, h in enumerate(headers):
            w = widths[i]
            lns = self.wrap_text(h, w - 10, font="F2", size=8.5)
            self.set_color(1.0, 1.0, 1.0)
            text_y = top_y - pad_top - 7
            for l in lns:
                self.draw_text(l, curr_x + 5, text_y, font="F2", size=8.5)
                text_y -= line_height
            curr_x += w
        self.y -= header_h
        
        # Draw rows
        for r_idx, row in enumerate(rows):
            row_h = calc_row_h(row, is_header=False)
            self.check_space(row_h)
            
            top_y = self.y
            bg_color = (0.97, 0.98, 0.99) if r_idx % 2 == 1 else (1.0, 1.0, 1.0)
            self.draw_rect(self.margin_left, top_y - row_h, self.usable_width, row_h,
                           fill_rgb=bg_color, stroke_rgb=(0.82, 0.85, 0.88), line_width=0.5)
            
            curr_x = self.margin_left
            for i, cell in enumerate(row):
                w = widths[i]
                is_bold_col = (i == 0)
                f_name = "F2" if is_bold_col else "F1"
                lns = self.wrap_text(cell, w - 10, font=f_name, size=8.0)
                self.set_color(0.12, 0.16, 0.23)
                text_y = top_y - pad_top - 7
                for l in lns:
                    self.draw_text(l, curr_x + 5, text_y, font=f_name, size=8.0)
                    text_y -= line_height
                # vertical border
                if i > 0:
                    self.draw_line(curr_x, top_y, curr_x, top_y - row_h, width=0.5, r=0.82, g=0.85, b=0.88)
                curr_x += w
            self.y -= row_h
        self.y -= 8

    def compile_pdf(self):
        objects = []
        
        def add_object(content_bytes):
            objects.append(content_bytes)
            return len(objects)  # 1-based object number
        
        # Obj 1: Catalog
        catalog_obj_num = 1
        # Obj 2: Pages
        pages_obj_num = 2
        # Fonts: Obj 3..7
        font_obj_nums = {}
        for fkey, basefont in self.fonts.items():
            font_def = f"<< /Type /Font /Subtype /Type1 /BaseFont {basefont} >>".encode("latin1")
            font_obj_nums[fkey] = add_object(font_def)  # 1, 2, ...
            
        # Font resources dictionary
        fonts_dict_str = " ".join([f"/{k} {font_obj_nums[k]} 0 R" for k in self.fonts.keys()])
        
        # Create page objects & stream objects
        page_ref_nums = []
        for page_cmds in self.pages:
            content_stream = "".join(page_cmds).encode("latin1")
            stream_len = len(content_stream)
            stream_obj_content = (f"<< /Length {stream_len} >>\nstream\n".encode("latin1") +
                                  content_stream +
                                  b"\nendstream")
            content_obj_num = add_object(stream_obj_content)
            
            page_obj_content = (f"<< /Type /Page\n"
                                f"   /Parent {pages_obj_num} 0 R\n"
                                f"   /MediaBox [0 0 {self.width:.2f} {self.height:.2f}]\n"
                                f"   /Contents {content_obj_num} 0 R\n"
                                f"   /Resources << /Font << {fonts_dict_str} >> >>\n"
                                f">>").encode("latin1")
            page_obj_num = add_object(page_obj_content)
            page_ref_nums.append(page_obj_num)
            
        # Obj 2: Pages object
        kids_str = " ".join([f"{num} 0 R" for num in page_ref_nums])
        pages_obj_content = (f"<< /Type /Pages\n"
                             f"   /Kids [{kids_str}]\n"
                             f"   /Count {len(page_ref_nums)}\n"
                             f">>").encode("latin1")
        # Place pages at index 1 (obj 2)
        # Note: in add_object we appended to list, so let's properly structure objects
        # To avoid confusion, let's assemble cleanly in a 2-pass array:
        pass

# Let's write a dedicated, rock-solid assembly function:
class CompletePDFWriter:
    def __init__(self, filename):
        self.filename = filename
        self.width = 595.28
        self.height = 841.89
        self.margin_left = 40.0
        self.margin_right = 40.0
        self.margin_top = 45.0
        self.margin_bottom = 45.0
        self.usable_width = self.width - self.margin_left - self.margin_right
        self.pages = []
        self.cur_cmds = []
        self.y = self.height - self.margin_top
        self.start_new_page(first=True)

    def start_new_page(self, first=False):
        if not first:
            self.pages.append(self.cur_cmds)
            self.cur_cmds = []
        self.y = self.height - self.margin_top
        p = len(self.pages) + 1
        if p > 1:
            # Header
            self.cur_cmds.append(f"0.4 0.45 0.5 rg BT /F4 8 Tf {self.margin_left:.2f} {self.height - 28:.2f} Td (CryptoShield - Architecture & Operational Guide (Phases 1-10)) Tj ET\n")
            self.cur_cmds.append(f"0.8 0.85 0.9 RG 0.5 w {self.margin_left:.2f} {self.height - 32:.2f} m {self.width - self.margin_right:.2f} {self.height - 32:.2f} l S\n")

    def check_space(self, h):
        if self.y - h < self.margin_bottom:
            self.start_new_page()

    def escape(self, s):
        return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    def wrap(self, text, max_w, font="F1", size=9.5):
        char_w = 0.54 * size
        if font in ["F2", "F5"]:
            char_w = 0.58 * size
        max_chars = max(8, int(max_w / char_w))
        words = text.split(" ")
        lines, cur, cur_len = [], [], 0
        for w in words:
            wl = len(w)
            if cur_len + wl + (1 if cur else 0) <= max_chars:
                cur.append(w)
                cur_len += wl + (1 if cur else 0)
            else:
                if cur:
                    lines.append(" ".join(cur))
                cur, cur_len = [w], wl
        if cur:
            lines.append(" ".join(cur))
        return lines

    def add_title(self, title, subtitle):
        self.check_space(65)
        esc_t = self.escape(title)
        esc_s = self.escape(subtitle)
        self.cur_cmds.append(f"0.06 0.09 0.16 rg BT /F2 17 Tf {self.margin_left:.2f} {self.y - 18:.2f} Td ({esc_t}) Tj ET\n")
        self.y -= 26
        self.cur_cmds.append(f"0.01 0.45 0.70 rg BT /F1 9 Tf {self.margin_left:.2f} {self.y - 8:.2f} Td ({esc_s}) Tj ET\n")
        self.y -= 14
        self.cur_cmds.append(f"0.01 0.52 0.78 RG 1.5 w {self.margin_left:.2f} {self.y - 2:.2f} m {self.width - self.margin_right:.2f} {self.y - 2:.2f} l S\n")
        self.y -= 12

    def add_banner(self, text):
        lines = self.wrap(text, self.usable_width - 24, font="F1", size=8.5)
        h = len(lines) * 11 + 14
        self.check_space(h + 8)
        top = self.y
        # Box background
        self.cur_cmds.append(f"0.94 0.97 1.0 rg {self.margin_left:.2f} {top - h:.2f} {self.usable_width:.2f} {h:.2f} re f\n")
        # Left border
        self.cur_cmds.append(f"0.01 0.52 0.78 rg {self.margin_left:.2f} {top - h:.2f} 4 {h:.2f} re f\n")
        # Text
        ty = top - 12
        for l in lines:
            esc = self.escape(l)
            self.cur_cmds.append(f"0.01 0.40 0.60 rg BT /F1 8.5 Tf {self.margin_left + 12:.2f} {ty:.2f} Td ({esc}) Tj ET\n")
            ty -= 11
        self.y -= h + 10

    def add_h2(self, text):
        self.check_space(40)
        self.y -= 6
        esc = self.escape(text)
        self.cur_cmds.append(f"0.01 0.41 0.63 rg BT /F2 12 Tf {self.margin_left:.2f} {self.y - 12:.2f} Td ({esc}) Tj ET\n")
        self.y -= 15
        self.cur_cmds.append(f"0.85 0.88 0.92 RG 0.8 w {self.margin_left:.2f} {self.y - 2:.2f} m {self.width - self.margin_right:.2f} {self.y - 2:.2f} l S\n")
        self.y -= 8

    def add_h3(self, text):
        self.check_space(30)
        esc = self.escape(text)
        self.cur_cmds.append(f"0.12 0.16 0.23 rg BT /F2 10.5 Tf {self.margin_left:.2f} {self.y - 10:.2f} Td ({esc}) Tj ET\n")
        self.y -= 15

    def add_h4(self, text):
        self.check_space(25)
        esc = self.escape(text)
        self.cur_cmds.append(f"0.20 0.25 0.33 rg BT /F2 9.5 Tf {self.margin_left:.2f} {self.y - 9:.2f} Td ({esc}) Tj ET\n")
        self.y -= 13

    def add_p(self, text, size=9.0, spacing=12):
        lines = self.wrap(text, self.usable_width, font="F1", size=size)
        self.check_space(len(lines) * spacing + 4)
        for l in lines:
            esc = self.escape(l)
            self.cur_cmds.append(f"0.12 0.16 0.23 rg BT /F1 {size} Tf {self.margin_left:.2f} {self.y - size:.2f} Td ({esc}) Tj ET\n")
            self.y -= spacing
        self.y -= 3

    def add_bullet(self, bold_prefix, text, size=9.0, spacing=12, indent=12):
        full_text = f"{bold_prefix} {text}" if bold_prefix else text
        lines = self.wrap(full_text, self.usable_width - indent, font="F1", size=size)
        self.check_space(len(lines) * spacing + 3)
        # Bullet dot
        self.cur_cmds.append(f"0.01 0.52 0.78 rg BT /F2 {size} Tf {self.margin_left + 2:.2f} {self.y - size:.2f} Td (>) Tj ET\n")
        for l in lines:
            esc = self.escape(l)
            self.cur_cmds.append(f"0.15 0.20 0.28 rg BT /F1 {size} Tf {self.margin_left + indent:.2f} {self.y - size:.2f} Td ({esc}) Tj ET\n")
            self.y -= spacing
        self.y -= 2

    def add_table(self, headers, rows, col_weights):
        total_w = sum(col_weights)
        widths = [w / total_w * self.usable_width for w in col_weights]
        line_h = 10.5
        pad = 4

        def calc_h(cells, font="F1"):
            max_ln = 1
            for i, c in enumerate(cells):
                lns = self.wrap(c, widths[i] - 8, font=font, size=8.0)
                max_ln = max(max_ln, len(lns))
            return max_ln * line_h + pad * 2

        head_h = calc_h(headers, "F2")
        self.check_space(head_h + 30)

        # Header draw
        top = self.y
        self.cur_cmds.append(f"0.06 0.09 0.16 rg {self.margin_left:.2f} {top - head_h:.2f} {self.usable_width:.2f} {head_h:.2f} re f\n")
        cx = self.margin_left
        for i, h in enumerate(headers):
            lns = self.wrap(h, widths[i] - 8, font="F2", size=8.0)
            ty = top - pad - 6.5
            for l in lns:
                esc = self.escape(l)
                self.cur_cmds.append(f"1.0 1.0 1.0 rg BT /F2 8.0 Tf {cx + 4:.2f} {ty:.2f} Td ({esc}) Tj ET\n")
                ty -= line_h
            cx += widths[i]
        self.y -= head_h

        # Rows draw
        for r_idx, r in enumerate(rows):
            rh = calc_h(r, "F1")
            self.check_space(rh)
            top = self.y
            bg = "0.96 0.97 0.99" if r_idx % 2 == 1 else "1.0 1.0 1.0"
            self.cur_cmds.append(f"{bg} rg {self.margin_left:.2f} {top - rh:.2f} {self.usable_width:.2f} {rh:.2f} re f\n")
            # row border
            self.cur_cmds.append(f"0.82 0.85 0.88 RG 0.5 w {self.margin_left:.2f} {top - rh:.2f} {self.usable_width:.2f} {rh:.2f} re S\n")
            
            cx = self.margin_left
            for i, c in enumerate(r):
                fnt = "F2" if (i == 0 and len(r) == 4) else "F1"
                lns = self.wrap(c, widths[i] - 8, font=fnt, size=7.8)
                ty = top - pad - 6.5
                for l in lns:
                    esc = self.escape(l)
                    self.cur_cmds.append(f"0.12 0.16 0.23 rg BT /{fnt} 7.8 Tf {cx + 4:.2f} {ty:.2f} Td ({esc}) Tj ET\n")
                    ty -= line_h
                cx += widths[i]
            self.y -= rh
        self.y -= 8

    def build(self):
        if self.cur_cmds:
            self.pages.append(self.cur_cmds)
        
        total_p = len(self.pages)
        for idx, page_cmds in enumerate(self.pages):
            pnum = idx + 1
            # Add footer
            page_cmds.append(f"0.75 0.78 0.82 RG 0.5 w {self.margin_left:.2f} 30.00 m {self.width - self.margin_right:.2f} 30.00 l S\n")
            page_cmds.append(f"0.40 0.45 0.50 rg BT /F1 7.5 Tf {self.margin_left:.2f} 20.00 Td (CryptoShield University Lab Defense Platform - Internal Team Guide) Tj ET\n")
            esc_p = self.escape(f"Page {pnum} of {total_p}")
            page_cmds.append(f"0.40 0.45 0.50 rg BT /F2 7.5 Tf {self.width - self.margin_right - 55:.2f} 20.00 Td ({esc_p}) Tj ET\n")

        # PDF Compilation
        # 1: Catalog
        # 2: Pages
        # 3..6: Fonts (F1=Helvetica, F2=Helvetica-Bold, F3=Courier, F4=Helvetica-Oblique)
        # Content Streams & Page Objects
        obj_table = {}  # obj_num -> bytes
        
        obj_table[1] = b"<< /Type /Catalog /Pages 2 0 R >>"
        
        # Fonts
        obj_table[3] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
        obj_table[4] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>"
        obj_table[5] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>"
        obj_table[6] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Oblique >>"
        
        next_obj = 7
        page_obj_nums = []
        for p_cmds in self.pages:
            c_stream = "".join(p_cmds).encode("latin1")
            stream_obj_num = next_obj
            next_obj += 1
            page_obj_num = next_obj
            next_obj += 1
            
            obj_table[stream_obj_num] = f"<< /Length {len(c_stream)} >>\nstream\n".encode("latin1") + c_stream + b"\nendstream"
            obj_table[page_obj_num] = (
                f"<< /Type /Page /Parent 2 0 R\n"
                f"   /MediaBox [0 0 {self.width:.2f} {self.height:.2f}]\n"
                f"   /Contents {stream_obj_num} 0 R\n"
                f"   /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R /F4 6 0 R >> >>\n"
                f">>"
            ).encode("latin1")
            page_obj_nums.append(page_obj_num)

        kids_refs = " ".join([f"{n} 0 R" for n in page_obj_nums])
        obj_table[2] = f"<< /Type /Pages /Kids [{kids_refs}] /Count {len(page_obj_nums)} >>".encode("latin1")
        
        # Assemble file
        out = bytearray()
        out.extend(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        
        total_objs = max(obj_table.keys())
        offsets = {}
        for num in range(1, total_objs + 1):
            offsets[num] = len(out)
            data = obj_table[num]
            out.extend(f"{num} 0 obj\n".encode("latin1"))
            out.extend(data)
            out.extend(b"\nendobj\n")
            
        xref_offset = len(out)
        out.extend(f"xref\n0 {total_objs + 1}\n".encode("latin1"))
        out.extend(b"0000000000 65535 f \n")
        for num in range(1, total_objs + 1):
            out.extend(f"{offsets[num]:010d} 00000 n \n".encode("latin1"))
            
        out.extend(
            f"trailer\n<< /Size {total_objs + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n".encode("latin1")
        )
        
        with open(self.filename, "wb") as f:
            f.write(out)
        print(f"Generated PDF: {self.filename} ({len(out)} bytes, {total_p} pages)")

if __name__ == "__main__":
    pdf = CompletePDFWriter("docs/CryptoShield_Full_Architecture_Guide.pdf")
    
    # Document header
    pdf.add_title(
        "CryptoShield - Full Architecture & Operational Guide",
        "Phases 1-10 Complete Defensive Platform | 280 Passing Tests (59 Modules, 100%) | NFSU Lab"
    )
    
    pdf.add_banner(
        "Welcome to the Full CryptoShield Architecture Guide! Now that all 10 project phases are complete (with 280 out of 280 automated tests passing across 59 test modules), this document serves as the complete reference for explaining the architecture, cryptographic and forensic concepts, PySide6 SOC Console, testing methodology, and end-to-end defensive workflow to your team."
    )
    
    # 1. Plain English
    pdf.add_h2("1. CryptoShield in Layman's Language: The Big Picture")
    pdf.add_h3("The Real-World Problem")
    pdf.add_p("Modern ransomware has evolved into 'Double Extortion':")
    pdf.add_bullet("The Theft (Exfiltration):", "First, attackers quietly read and copy your private documents, pack them into an archive, and sneak them out over the network. They threaten to publish them if you don't pay.")
    pdf.add_bullet("The Lockup (Encryption):", "Next, they run through your hard drive at lightning speed, scrambling every file into gibberish (encrypting them) and deleting your backups so you can't restore them.")
    
    pdf.add_h3("The CryptoShield Analogy: A High-Tech Bank & Embassy")
    pdf.add_p("Imagine an embassy or high-security bank. CryptoShield is not just a single lock on the front door; it is an integrated immune system:")
    pdf.add_bullet("The Tripwires (Canary Files):", "Fake stacks of money left on tables. If anyone so much as touches them, silent alarms blare.")
    pdf.add_bullet("The Security Guards & Cameras (Monitoring):", "Guards watching who touches what file, how fast they are opening drawers, and what programs are running.")
    pdf.add_bullet("The Suspicion Brain (Threat Scorer):", "Distinguishes a busy accountant from a masked burglar shoving files into bags.")
    pdf.add_bullet("The Blast Doors (Containment):", "The instant a thief is spotted, steel shutters drop over the vault door, and the suspect is disarmed and frozen.")
    pdf.add_bullet("The Border Customs Checkpoint (DLP Gate):", "Even if a thief grabs documents, they cannot walk out without customs inspecting every box. Confidential files are stopped cold before a single byte leaves.")
    pdf.add_bullet("The Underground Vault (Crypto Vault & Recovery):", "A hidden, sealed backup taken earlier. Even if a fire burns down the front desk, original documents are decrypted in staging, verified bit-for-bit, and restored.")
    pdf.add_bullet("The Black Box & Notary Seal (Phase 9 - Forensics):", "After an incident, an automated investigator fuses every alarm, customs record, and recovery receipt into one tamper-evident dossier sealed with a SHA-256 fingerprint.")
    pdf.add_bullet("The Command Center Wall (Phase 10 - PySide6 SOC Console):", "A unified dark-mode console where operators watch live threat gauges, throw emergency blast-door switches, verify forensic seals, and run safe simulations on one IST clock.")
    
    # 2. Tech concepts
    pdf.add_h2("2. Technological Concepts Used (What They Mean & Why We Used Them)")
    pdf.add_p("Here is every major computer science, cryptographic, forensic, and desktop UI concept built into CryptoShield, explained in plain terms:")
    
    pdf.add_h3("A. Cryptography & Forensic Integrity Concepts")
    headers_a = ["Concept", "What It Is in Plain English", "Where & Why We Use It"]
    rows_a = [
        [
            "AES-256-GCM (Symmetric Authenticated Encryption)",
            "Think of this as an armored military lockbox. It scrambles data using a 256-bit key. GCM (Galois/Counter Mode) generates a cryptographic 'tamper-evident seal' (the 128-bit Auth Tag). If an attacker changes even one single bit on disk, GCM detects it immediately and refuses to open.",
            "Used by CryptoEngine to encrypt files into .cso containers for snapshots, and by RestorationManager to authenticate plaintext before commit."
        ],
        [
            "RSA-3072 & RSA-OAEP (Asymmetric Public/Private Encryption)",
            "A two-key system: a Public Key that can only lock the safe, and a Private Key needed to open it. OAEP with SHA-256 prevents mathematical pattern attacks.",
            "Used by KeyManager and SnapshotManager. Each snapshot gets its own random AES key, wrapped with RSA-OAEP so it cannot open without the master private key."
        ],
        [
            "Argon2id (Memory-Hard Key Derivation)",
            "A password hasher that deliberately uses 64 MiB of RAM, 3 iterations, and 4 lanes. It makes brute-force password guessing impractical, even for specialized GPUs.",
            "Used in Envelope V2 (Argon2id-AES256GCM) to protect the master RSA private key on disk against offline brute-force cracking."
        ],
        [
            "SHA-256 (Cryptographic Hash Function)",
            "A one-way mathematical fingerprint. Change a single byte in a file, and its 64-character hex fingerprint changes completely.",
            "Used in baseline_manifest.json, RecoveryAssessor, and RestorationManager to verify every restored file matches its original 100%."
        ],
        [
            "HMAC-SHA256 (Keyed-Hash Message Authentication)",
            "A digital signature created with a secret key. It proves that a marker file was written by CryptoShield and has not been forged or moved.",
            "Used in .cryptoshield_lab_marker and .cryptoshield_recovery_marker. Prevents touching files outside authorized lab or recovery folders."
        ],
        [
            "Cryptographic Chain of Custody & Dossier Seal (Phase 9)",
            "Freezing an entire incident dossier by computing a deterministic SHA-256 digest over canonical sorted JSON (sort_keys=True), binding the baseline manifest hash and quarantined evidence hashes.",
            "Used by ForensicDossier (compute_dossier_hash) and ReportExporter (verify_dossier_seal). Editing one metric or timestamp breaks the seal."
        ]
    ]
    pdf.add_table(headers_a, rows_a, [28, 44, 28])
    
    pdf.add_h3("B. Operating System, Forensic & Desktop UI Concepts")
    headers_b = ["Concept", "What It Is in Plain English", "Where & Why We Use It"]
    rows_b = [
        [
            "Canary Files / Honeypots",
            "Deceptive 'bait' files (e.g., passwords_master_backup.json, executive_salaries_2026.csv) placed quietly in directories. Normal users never touch them; ransomware inevitably hits them first.",
            "Used in CanaryAnalyzer and ReadBurstDetector. Touching a canary awards +50 to +60 threat points and triggers emergency alerts."
        ],
        [
            "File System Telemetry (watchdog)",
            "Hooking into the OS filesystem notification layer to be notified the exact millisecond a file is created, modified, renamed, or deleted.",
            "Used in FilesystemMonitor to track rapid file changes across the 20,000 files in our lab."
        ],
        [
            "Process Inspection (psutil)",
            "Inspecting the OS process table to see what program is running, who launched it, its PID, start time, and exact executable path.",
            "Used in ProcessMonitor and ControlledProcessRegistry to attribute simulator activity accurately without guessing."
        ],
        [
            "Sliding Time Windows",
            "Evaluating activity over rolling intervals (1s, 5s, 10s, 30s) rather than isolated snapshots.",
            "Used in BehaviorAnalyzer and ReadBurstDetector to distinguish normal edits from rapid ransomware bursts."
        ],
        [
            "Pub/Sub Event Bus",
            "A central thread-safe broadcasting station in app/core/event_bus.py. Subsystems emit typed events without calling each other directly.",
            "Connects monitoring, detection, containment, exfiltration, DLP, recovery, Phase 9 auto-reporting, and Phase 10 live GUI updates."
        ],
        [
            "PID Reuse Protection",
            "Operating systems reuse PIDs once a program exits. Checking PID alone risks stopping an innocent app started later.",
            "ControlledProcessRegistry checks PID + start-time + executable path + owned handle before ProcessController stops any simulator."
        ],
        [
            "Pre-Transmission Gate (DLP)",
            "Intercepting data before it hits the network socket, enforcing ALLOW, ALERT, REQUIRE_APPROVAL, or BLOCK in memory.",
            "Used in DLPTransferGate and DLPApprovalManager (APR-* tokens) to guarantee zero-byte leakage of restricted or canary data."
        ],
        [
            "Forensic Aggregation & MITRE ATT&CK Mapping (Phase 9)",
            "Fusing telemetry from detection, containment, recovery, DLP, and exfiltration into one chronological dossier with academic KPIs and MITRE tags (T1486, T1083, T1005, T1074, T1048).",
            "Implemented in ForensicAggregator and ReportExporter, exporting JSON, Markdown, CSV, and HTML reports under runtime/reports/."
        ],
        [
            "Thread-Safe Qt Signal Bridge & Async Workers (Phase 10)",
            "Background threads cannot safely touch GUI widgets directly. A bridge converts EventBus events into Qt queued signals while QThread workers run heavy tasks off the UI thread.",
            "Implemented in EventBusBridge (app/ui/bridge.py) and AsyncWorker (app/ui/workers.py), keeping the 8-tab PySide6 console responsive."
        ],
        [
            "Centralized Temporal Sync (IST / UTC+05:30)",
            "Normalizing every clock, event timestamp, log line, and dossier entry to Indian Standard Time (IST).",
            "Implemented in app/core/time.py (now_ist, format_ist, parse_iso_to_ist) so cross-subsystem timelines align to the microsecond."
        ]
    ]
    pdf.add_table(headers_b, rows_b, [28, 44, 28])
    
    # 3. Tests
    pdf.add_h2("3. What Are the Multiple Tests For? (280 Tests Explained)")
    pdf.add_p("CryptoShield includes 59 test files with 280 total automated tests (280 / 280 passing). In high-stakes security and cryptography software, you cannot guess or assume code works - you must prove it against edge cases, tampering, concurrency bugs, and simulated attacks.")
    
    pdf.add_bullet("1. Safety, Config & Lab Foundation Tests (25 tests - test_safety.py, test_config.py, test_lab_*.py, test_manifest.py, test_dataset_generator.py):", "Directory traversal rejection, symlink checks, signed markers, CRYPTOSHIELD_RUNTIME_DIR isolation, deterministic dataset synthesis, and SHA-256 baseline auditing.")
    pdf.add_bullet("2. Monitoring, Detection & Containment Tests (85 tests - test_*monitor*.py, test_canary_*.py, test_behavior_analyzer.py, test_threat_scorer.py, test_containment_*.py):", "High-throughput telemetry, burst encryption vs. normal typing, canary scoring (+50/+60), LabWriteGate closure, PID-reuse-safe containment, and post-containment write rejection.")
    pdf.add_bullet("3. Cryptographic Vault & Anti-Tampering Tests (43 tests - test_vault_*.py):", "Bit-flipping in .cso files (AES-GCM tag mismatch), substituted manifests, Argon2id V2 wrong-passphrase rejection, and RSA-OAEP session key wrapping.")
    pdf.add_bullet("4. Bit-for-Bit Recovery Tests (28 tests - test_recovery_*.py):", "Multi-threaded damage assessment, isolated recovery workspace markers, staging decryption, evidence quarantine, and 100% SHA-256 hash match after restore.")
    pdf.add_bullet("5. Exfiltration & DLP Policy Tests (52 tests - test_exfiltration_*.py, test_dlp_*.py):", "Multi-department read bursts, .zip staging detection, loopback boundaries (127.0.0.1), zero-byte BLOCK enforcement, and APR-* approval workflows.")
    pdf.add_bullet("6. Forensic Reporting & Temporal Sync Tests (26 tests - test_forensic_*.py, test_timezone_sync.py):", "ForensicAggregator timeline fusion, MITRE ATT&CK mapping, academic KPI math, 4-format export (JSON, Markdown, CSV, HTML), verify_dossier_seal() tamper detection, ControlledForensicDemo, and IST (UTC+05:30) clock synchronization.")
    pdf.add_bullet("7. PySide6 Desktop GUI & E2E Console Tests (21 tests - test_ui_*.py):", "Headless (--offscreen) tests covering the dark SOC theme, KPICard/ThreatGauge/EventTable widgets, EventBusBridge, AsyncWorker, all 8 operational tabs, all 5 interactive simulations, and full live multi-tab propagation (test_ui_stage5_e2e_integration.py).")
    
    # 4. Workflow
    pdf.add_h2("4. The Complete End-to-End Workflow (Step-by-Step)")
    pdf.add_p("Here is how CryptoShield operates end-to-end - both under the hood and live inside the PySide6 SOC Console (python -m app.main gui):")
    
    pdf.add_h4("Step 1: Peacetime Preparation (The Immune Blueprint)")
    pdf.add_p("CryptoShield initializes runtime/lab/ with an HMAC-SHA256 .cryptoshield_lab_marker, synthesizes up to 20,000 corporate files, compiles baseline_manifest.json, plants Canary honeypots, and creates an encrypted Vault Snapshot (SNAP-XXXX). In the GUI, the top ribbon reads LAB: VALID, GATE: UNLOCKED, THREAT: 0 NORMAL, and DLP: DEFAULT.")
    
    pdf.add_h4("Step 2: Attack Phase 1 - Data Harvesting (The Theft)")
    pdf.add_p("An attacker reads sensitive files across Engineering/Research, HR, and Finance. ReadBurstDetector flags the multi-department read spike and broadcasts telemetry over EventBus to ExfiltrationCorrelator.")
    
    pdf.add_h4("Step 3: Attack Phase 2 - Staging")
    pdf.add_p("Stolen documents are gathered and compressed into confidential_export.zip. StagingDetector detects the staging archive creation in real time.")
    
    pdf.add_h4("Step 4: Attack Phase 3 - Exfiltration Blocked by DLP")
    pdf.add_p("The simulator attempts to stream the archive to the loopback MockReceiver (127.0.0.1). DLPTransferGate intercepts the transfer in memory before socket egress, inspects its classification/canary flags, halts it with zero bytes leaked, logs to runtime/dlp/audit.log, and updates Tab 6 (Exfiltration & DLP).")
    
    pdf.add_h4("Step 5: Attack Phase 4 - Ransomware Burst & Canary Tripwire")
    pdf.add_p("Ransomware rapidly scrambles files and touches a canary. CanaryAnalyzer spikes threat points (+50/+60), BehaviorAnalyzer catches the write burst, and ThreatScorer hits CRITICAL (95-100/100). On the GUI Dashboard, Canaries flip to BREACHED, ThreatGauge turns red, and the top ribbon shows THREAT: CRITICAL.")
    
    pdf.add_h4("Step 6: Instant Containment")
    pdf.add_p("IncidentManager triggers ContainmentManager: LabWriteGate locks (.write_gate_state set to locked; ribbon turns red GATE: LOCKED), ProcessController verifies PID + start-time + path in ControlledProcessRegistry and stops the simulator cleanly, and ContainmentVerifier confirms zero post-containment writes.")
    
    pdf.add_h4("Step 7: Cryptographic Restoration (The Cure)")
    pdf.add_p("RecoveryAssessor compares disk files against the snapshot manifest in parallel. Damaged files are quarantined as evidence. RestorationManager decrypts clean .cso objects into staging, verifies both the AES-GCM auth tag and SHA-256 digest, and atomically restores every file (tracked live on Tab 5's progress bar).")
    
    pdf.add_h4("Step 8: Automated Forensic Dossier & Chain-of-Custody Seal (Phase 9)")
    pdf.add_p("When the incident resolves (SECURITY_INCIDENT_RESOLVED), ForensicCoordinator invokes ForensicAggregator and ReportExporter to compile a sealed ForensicDossier (REP-XXXXXXXX) under runtime/reports/ in JSON, Markdown, CSV, and HTML formats - complete with IST timelines, MITRE ATT&CK mappings, academic KPIs, and a dossier_sha256 seal.")
    
    pdf.add_h4("Step 9: Operator Audit & Verification in the SOC Console (Phase 10)")
    pdf.add_p("In Tab 7 (Forensic Reports), the operator clicks Cryptographically Verify Seal ([PASS] VALID), reviews the Academic KPIs (0 Bytes Leaked, 100.0% SHA-256 match) and IST timeline, and runs Tab 2's Integrity Audit across all 20,000 baseline files (100% matched, 0 modified, 0 missing).")

    # 5. PySide6 SOC Console Overview
    pdf.add_h2("5. PySide6 SOC Console (8 Operational Tabs) & Key CLI Commands")
    pdf.add_bullet("Top Ribbon & Status Bar:", "Live LAB, GATE, THREAT, and DLP badges, live IST clock, active lab directory, and EventBus Bridge: ONLINE status.")
    pdf.add_bullet("8 Subsystem Tabs:", "(1) Dashboard & Telemetry, (2) Lab & Dataset Engine, (3) Threat Containment, (4) Cryptographic Vault, (5) Recovery & Restoration, (6) Exfiltration & DLP, (7) Forensic Reports, and (8) Simulation Testbed (5 one-click scenarios with Demonstration / Extended / Rapid pacing).")
    pdf.add_bullet("Phase 9 & 10 CLI Entrypoints:", "python -m app.main report {list, inspect, generate, verify, demo} and python -m app.main gui [--offscreen].")
    
    # 6. Summary Checklist Table
    pdf.add_h2("6. Summary Checklist of All Completed Phases (1 through 10)")
    headers_c = ["Phase", "Subsystem", "Core Purpose in Simple Words", "Tests Passing"]
    rows_c = [
        ["1", "Lab & Dataset Engine", "Builds a realistic 20,000-file corporate playground with SHA-256 fingerprints & safety boundaries.", "25 / 25"],
        ["2", "File Telemetry & Sentry", "Cameras and microphones recording every file read, edit, delete, and process start.", "25 / 25"],
        ["3", "Threat Brain & Scoring", "Weighs suspicious activity and canary breaches to calculate a 0-100 threat score.", "28 / 28"],
        ["4", "Blast Doors & Containment", "Drops LabWriteGate and safely stops registered simulators without hurting host apps.", "32 / 32"],
        ["5", "Cryptographic Vault", "Indestructible backups encrypted with AES-256-GCM, RSA-3072, and Argon2id.", "43 / 43"],
        ["6", "Two-Stage Restoration", "Medical recovery verifying GCM tags and SHA-256 hashes before atomic file restore.", "28 / 28"],
        ["7", "Exfiltration Radar", "Detects mass reading, folder harvesting, archive staging (.zip), and loopback transfers.", "25 / 25"],
        ["8", "Data Loss Prevention (DLP)", "Customs gate that inspects and halts confidential data transfers before socket egress.", "27 / 27"],
        ["9", "Forensic Incident Reporting", "Fuses multi-subsystem timelines, MITRE ATT&CK tags, 4-format exports, and SHA-256 custody seals.", "21 / 21"],
        ["10", "PySide6 Desktop GUI & Integration", "8-tab dark SOC console with thread-safe EventBusBridge, AsyncWorker, and 5 simulation demos.", "21 / 21"],
        ["Sync", "Temporal Sync (IST)", "Synchronizes all event buses, logs, dossiers, and GUI clocks to Indian Standard Time (UTC+05:30).", "5 / 5"],
        ["Total", "Phases 1-10 (59 Test Files)", "Complete End-to-End Double-Extortion Defense Platform", "280 / 280"]
    ]
    pdf.add_table(headers_c, rows_c, [10, 30, 46, 14])
    
    pdf.build()

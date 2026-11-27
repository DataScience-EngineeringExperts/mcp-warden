# Parser image notices

MCP-Warden worker and shared framing code are distributed under the MIT license
copied from this repository to `/worker/LICENSE` in the image.

The image installs original hash-verified wheels and retains their bundled
copyright and license files under Python's `site-packages` distribution metadata:

| Distribution | Version | License |
|---|---|---|
| pypdf | 7.1.0 | BSD-3-Clause |
| markdown-it-py | 4.3.0 | MIT |
| mdurl | 0.1.2 | MIT |

Keep those original notices with any redistribution. The Python interpreter and
base operating-system components retain the notices supplied by the pinned
official Python image. This file identifies dependencies; it does not replace
their complete license texts.

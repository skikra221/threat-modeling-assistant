import streamlit as st
import streamlit.components.v1 as components

st.set_page_config(layout="wide")

input_mode = st.segmented_control(
    "Choose input type",
    ["Architecture File", "Android APK"],
    default="Architecture File"
)

st.file_uploader("Upload", type=["yaml", "yml", "json"])

components.html("""
<script>
    setTimeout(() => {
        const uploader = window.parent.document.querySelector('[data-testid="stFileUploaderDropzone"]');
        const segmented = window.parent.document.querySelector('[data-testid="stSegmentedControl"]');
        
        let dump = "UPLOADER:\\n" + (uploader ? uploader.outerHTML : "Not found") + "\\n\\n";
        dump += "SEGMENTED:\\n" + (segmented ? segmented.outerHTML : "Not found");
        
        // Write it to a file using an API call if possible, but here we can't easily.
        // We can just display it.
        document.body.innerHTML = `<textarea id="dom_dump" style="width:100%; height:400px;">${dump.replace(/</g, "&lt;").replace(/>/g, "&gt;")}</textarea>`;
        // Use a dirty hack to send it to Streamlit backend by writing to an input and triggering event?
        // Let's just run it with playwright/puppeteer if we had it, but we can just use Streamlit's file system!
    }, 2000);
</script>
""", height=500)

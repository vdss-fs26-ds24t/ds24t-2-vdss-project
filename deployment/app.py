import streamlit as st
import streamlit.components.v1 as components

st.set_page_config(layout="wide")
html = open("eda/dashboard.html", "r", encoding="utf-8").read()
components.html(html, height=950, scrolling=True)

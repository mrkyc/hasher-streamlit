import streamlit as st
import hashlib
import pyperclip  # Uncomment this line if you want to use the clipboard feature in the non-cloud version


def compute_hash(algorithm, rounds, string):
    digest = string
    for _ in range(rounds):
        if algorithm == "MD5":
            digest = hashlib.md5(digest.encode()).hexdigest()
        elif algorithm == "SHA1":
            digest = hashlib.sha1(digest.encode()).hexdigest()
        elif algorithm == "SHA224":
            digest = hashlib.sha224(digest.encode()).hexdigest()
        elif algorithm == "SHA256":
            digest = hashlib.sha256(digest.encode()).hexdigest()
        elif algorithm == "SHA384":
            digest = hashlib.sha384(digest.encode()).hexdigest()
        elif algorithm == "SHA512":
            digest = hashlib.sha512(digest.encode()).hexdigest()
        elif algorithm == "BLAKE2B":
            digest = hashlib.blake2b(digest.encode()).hexdigest()
        elif algorithm == "BLAKE2S":
            digest = hashlib.blake2s(digest.encode()).hexdigest()
        elif algorithm == "SHA3_224":
            digest = hashlib.sha3_224(digest.encode()).hexdigest()
        elif algorithm == "SHA3_256":
            digest = hashlib.sha3_256(digest.encode()).hexdigest()
        elif algorithm == "SHA3_384":
            digest = hashlib.sha3_384(digest.encode()).hexdigest()
        elif algorithm == "SHA3_512":
            digest = hashlib.sha3_512(digest.encode()).hexdigest()
        elif algorithm == "SHAKE_128":
            digest = hashlib.shake_128(digest.encode()).hexdigest(32)
        elif algorithm == "SHAKE_256":
            digest = hashlib.shake_256(digest.encode()).hexdigest(64)

    return digest


def main():
    st.title("Hasher")
    if st.session_state.get("string_to_hash") is None:
        st.session_state.string_to_hash = ""
    if st.session_state.get("string_hashed") is None:
        st.session_state.string_hashed = ""

    algorithm = st.selectbox(
        "Select the hashing algorithm",
        [
            "MD5",
            "SHA1",
            "SHA224",
            "SHA256",
            "SHA384",
            "SHA512",
            "BLAKE2B",
            "BLAKE2S",
            "SHA3_224",
            "SHA3_256",
            "SHA3_384",
            "SHA3_512",
            "SHAKE_128",
            "SHAKE_256",
        ],
    )
    rounds = st.number_input("Enter the number of rounds", min_value=1, value=1)
    st.session_state.string_to_hash = st.text_input(
        "Enter your string to hash",
        value=st.session_state.string_to_hash,
        type="password",
        autocomplete="off",
    )

    if st.button("Hash :key:", use_container_width=True):
        st.session_state.string_hashed = compute_hash(
            algorithm, rounds, st.session_state.string_to_hash
        )

    st.text("Hashed string:")
    st.code(st.session_state.string_hashed)

    # Uncomment the following code if you want to use the clipboard feature in the non-cloud version
    # columns_clipboard_actions = st.columns(2)
    # with columns_clipboard_actions[0]:
    #     if st.button("Copy to clipboard", use_container_width=True):
    #         pyperclip.copy(st.session_state.string_hashed)
    #         st.success("Hash copied to clipboard")
    # with columns_clipboard_actions[1]:
    #     if st.button("Clear clipboard", use_container_width=True):
    #         pyperclip.copy("")
    #         st.success("Clipboard cleared")


main()

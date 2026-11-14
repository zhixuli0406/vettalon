from app.keys import make_signing_key, sign


def main():
    k = make_signing_key()
    print(sign(k, b"hello").hex())


if __name__ == "__main__":
    main()

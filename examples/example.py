from password_analyzer.core.analyzer import PasswordAnalyzer

# breach_checker=None -> análise totalmente local (sem rede).
analyzer = PasswordAnalyzer(breach_checker=None)

for password in ["maria123", "Maria123!", "xqzvjkpmw", "correct horse battery staple 42!"]:
    result = analyzer.analyze(password)
    print(f"{password!r}: {result.score}/4 ({result.label}) "
          f"~10^{result.guesses_log10:.1f} tentativas")

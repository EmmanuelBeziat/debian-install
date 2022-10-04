dns_available yes

# Activation du systeme Bayes
use_bayes 1
bayes_auto_learn 1
bayes_learn_to_journal 1
bayes_journal_max_size 0
bayes_path /var/spool/spamassassin/bayes

# Activation de l'auto whitelist
use_auto_whitelist 1
auto_whitelist_path /var/spool/spamassassin/auto-whitelist
auto_whitelist_file_mode 0666

# Activation de DCC
use_dcc 1
dcc_timeout 8
dcc_home /var/spool/spamassassin/dcc
dcc_path /usr/local/bin/dccproc
dcc_dccifd_path /usr/local/bin/dccifd

# Activation de Pyzor
use_pyzor 1

# Activatin de Razor
use_razor2 1
razor_timeout 8

# Optimisation des scores
score DCC_CHECK 4.500
score SPF_FAIL 10.000
score SPF_HELO_FAIL 10.000
score RAZOR2_CHECK 2.500
score RAZOR2_CF_RANGE_51_100 3.500
score BAYES_99 5.300
score BAYES_95 4.500
score BAYES_80 3.500
score BAYES_60 2.500
score BAYES_50 2.000

# Langages
ok_languages fr en
ok_locales fr en

required_hits 5

#add_header all Report _REPORT_
header Subject *** SPAM ***
report_safe

endif # Mail::spamassassin::Plugin::Shortcircuit
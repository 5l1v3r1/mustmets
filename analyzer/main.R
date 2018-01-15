# Load our lexicon
lexicon <- c("apple", "login")

# Load our data from MySQL
install.packages("RMariaDB")
library(DBI)
con <- dbConnect(RMariaDB::MariaDB(), group = "mustmets", default.file="./.my.cnf")
res <- dbSendQuery(con, "select 
	REVERSE(LEFT(REVERSE(D.name), INSTR(REVERSE(D.name), \".\"))) as tld,
                   D.name, D.blacklists, C.issuer, C.source,
                   C.signatureAlgorithm, C.algorithm, C.bit_size, count_seen,
                   TIMESTAMPDIFF(SECOND, C.notbefore, C.notafter) as duration
                   from domain_in_certificate DIN 
                   inner join domain D on D.id = DIN.domain_id
                   inner join certificate C on C.id = DIN.certificate_id
                   inner join (SELECT DIC.domain_id AS DID, COUNT(DIC.domain_id) AS count_seen
                   FROM domain_in_certificate DIC GROUP BY DIC.domain_id) DT
                   on DT.DID = D.id
                   WHERE D.id < 150000 AND LENGTH(REVERSE(LEFT(REVERSE(D.name), INSTR(REVERSE(D.name), \".\")))) > 2
                   ;")
data <- dbFetch(res, n=-1)
dbHasCompleted(res)
dbClearResult(res)
dbDisconnect(con)

data[is.na(data)] <- 0

# Let's start transforming our data, first convert tlds to binary dimensions
tlds <- unique(data$tld)
for (tld in tlds) {
  data[tld] <- vapply(data$tld, `==`, integer(1), tld)
}

# Drop the original tld column
data<-within(data, rm("tld"))

# Then do same for issuers
issuers <- unique(data$issuers)
for (issuer in issuers) {
  data[issuer] <- vapply(data$issuer, `==`, integer(1), issuer)
}
data<-within(data, rm("issuer"))

# Then blacklists
data["blacklists"] <- vapply(data$blacklists, `>`, integer(1), 0)

# Certstream sources
sources <- unique(data$source)
for (source in sources) {
  data[source] <- vapply(data$source, `==`, integer(1), source)
}
data<-within(data, rm("source"))

# Signature algos
signatures <- unique(data$signatureAlgorithm)
for (signatureAlgorithm in signatures) {
  data[signatureAlgorithm] <- vapply(data$signatureAlgorithm, `==`, integer(1), signatureAlgorithm)
}
data<-within(data, rm("signatureAlgorithm"))

# Bitsizes
bit_sizes <- unique(data$bit_size)
for (bit_size in bit_sizes) {
  data[paste("bit_size_", bit_size, sep="")] <- vapply(data$bit_size, `==`, integer(1), bit_size)
}
data<-within(data, rm("bit_size"))

# Cert lengths
data$duration <- as.numeric(as.character(data$duration))
measure_dur <- function (dur, min, max) {
  return(dur >= min & dur < max)
}

durations <- c("duration_low", "duration_mid", "duration_high")
for (duration in durations) {
  min <- switch(duration, duration_low=0, duration_mid=10713600, duration_high=32140800)
  max <- switch(duration, duration_low=10713600, duration_mid=32140800, duration_high=Inf)
  data[duration] <- vapply(data$duration, measure_dur, integer(1), min, max)
}
data<-within(data, rm("duration"))

# Key algos
algorithms <- unique(data$algorithm)
for (algorithm in algorithms) {
  data[algorithm] <- vapply(data$algorithm, `==`, integer(1), algorithm)
}
data<-within(data, rm("algorithm"))

# Seen counts
data$count_seen <- as.numeric(as.character(data$count_seen))
count_seens <- c("seen_low", "seen_mid", "seen_high")
for (count_seen in count_seens) {
  min <- switch(count_seen, seen_low=0, seen_mid=10, seen_high=30)
  max <- switch(count_seen, seen_low=10, seen_mid=30, seen_high=Inf)
  data[count_seen] <- vapply(data$count_seen, measure_dur, integer(1), min, max)
}
data<-within(data, rm("count_seen"))

# Then add lexicon data to bag of words, determine matches by using fuzzy agrep search
# This enables us to search for very fuzzy substrings within the domain names (for example "apple" from lexicon should match domain "login-appiesecure.xyz")
e_agrep <- function(sstring, pstring) {
  dist <- agrep(pstring, sstring, max.distance=list(substitutions=3, insertions=1, deletions=1))
  return(length(dist) > 0)
}

for (word in lexicon) {
  data[word] <- vapply(data$name, e_agrep, integer(1), word)
}

# With our enhanced data, train a naive bayes classifier
library("bnlearn")

data2 <- within(data, rm("name"))
data2[] <- lapply(data2, factor)

sample <- sample(1:nrow(data), 120000, replace=FALSE)
training <- data2[sample,]
#training <- within(training, rm("blacklists"))
#training <- within(training, rm("name"))
#training[] <- lapply(training, factor)
# drop factors with only one level
#training <- training[, sapply(training, nlevels) > 1]
test <- data2[-sample,]
#test <- within(test, rm("blacklists"))
#test <- within(test, rm("name"))
#test[] <- lapply(test, factor)
# drop factors with only one level
#test <- test[, sapply(test, nlevels) > 1]

system.time( bn <- naive.bayes(training, "blacklists") )
system.time( fitted <- bn.fit(bn, training))
system.time( pred <- predict(fitted, test) )
table("Predictions"= pred,  "Actual" = test[,"blacklists"])

# Use the trained model to predict new domains (PROFIT!) :)
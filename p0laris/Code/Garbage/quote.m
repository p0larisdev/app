/*
 *  quote.m
 *  p0laris
 *
 *  created on 1/14/22
 */

#include <mach/mach.h>
#include <stdlib.h>

char* quotes[] = {
	"saagarjha: These are garbage quotes",
	"constant state of fear and misery",
	"out of context ooc",
	"insert injoke here",
	"high amount of thing - bludood, 2019",
	"insert witty stuff here",
	"meme machine meme machine",
	"inject the memes into my bloodstream",
	"this has to be enough quotes",
	"lol jk",
	"tip: the jailbreak button jailbreaks your device",
	"RIP eddy wally",
	"https://www.youtube.com/watch?v=dQw4w9WgXcQ",
	"it's about drive",
	"it's about power",
	"we stay hungry",
	"we devour",
	"spoiler alert",
	"the good guy usually lives",
	"it's just business fella",
	"it's been nearly 10 years",
	"you forget a thousand things everyday",
	"how 'bout you make sure this is one of em",
	"is this thing even on?",
	"what's the deal with airline food",
//  "this is the fuck, my soggy friend - trevor phillips",
	"nama-go-fuck-yourself",
//  "why did you just go through the trouble of reversing this audio",
	"quotes are length limited",
	"unlike other things",
	"ghidra FTW",
	"if only home depot was open source",
	"then none of this would've been necessary, jk.",
	"take that how you will",
	"quotes are rants but short",
	"do midgets have night vision",
	"no really i need to know",
	"call me back im a human being not an animal",
	"wen eta",
	"420 blaze it",
	"smoke trees",
	"napleon the migdet",
	"pc load letter",
	"945a57ef24ca6ef91ad1e8ecdd3875eabf23c48d",
	"luv u guyz <3",
	"untethered soon, patience my children",
	"ABSA license is legit",
	"drama is cringe",
	"roses are red",
	"guns go bang",
	"steven segaul got carrot from dictator",
	"cd3f475ec97de47dc5505354444c456fd40a1ab9",
	"britcoin - pound 2.0",
	"cool mustache wario",
	"credit to bora for absolutely nothing",
	"$arm+leg",
	"eelslap.com",
	"RSA: an analogy i can't put here",
	"ratshit batshit",
	"https://www.youtube.com/watch?v=Fb5qybFOSKA",
	"Mj: weed-i-o’s got me good 🙂",
	"spv: insecurity researcher in chief",
	"csbypass eta s0n",
	"reply some stupid shit i need quotes",
	"carter get an intervention",
	"I got high and then",
	"e = 3 = π = √g",
	"Arch Linux: maintenance-free computing",
	"ios checkra1n coming soon from @0x8FF",
	"4 spaces or gtfo",
	"AI BMW water bottle",
	"p0laris eta s0n",
	"dab on the haters",
	"what happens if the haters dab back??? @jakepaul",
	"dated reference day",
	"fuck UAFs (except when i get to exploit them)",
	"23 to 54 KHz",
	"smoke trees",
	"there's one thing this video needs. KPOP!",
	"qwertyoruiop liked your reply",
	"11/19/2021 @ 10:39 AM",
	"https://www.youtube.com/watch?v=10yrPDf92hY",
	"https://www.youtube.com/watch?v=VOL0-EE3ieY",
	"'sup can a loc come up in your crib",
	"https://www.youtube.com/watch?v=QwDk4Eo0dwo",
	"https://www.youtube.com/watch?v=dBHj3m96LpI",
	"https://www.youtube.com/watch?v=IY2j_GPIqRA",
	"eat ass smoke grass and sled fast",
	"we out here",
	"wen eta jelbrek",
	"eta son",
	"eta s0n",
	"зачем вы потрудились перевести это",
	"неоригинальный",
	"not another russian gag",
	"you guys are why i drink",
	"written in C!",
	"smoke crack kids",
	"why are we still here, just to suffer?",
	"every night i can feel my leg",
	"this is the filler, filler oh ba da ba ba da boop"
	"something something whole video",
	"THIS IS THE FILLER!",
	"p0laris - now with over 100 quotes!",
	"don't quote me on this",
	"gatorade should be thicker",
	"how has no-one stopped me from jb dev???",
	"blaze it",
	"xx_420_blazit_xx",
	"al gore created the internet",
	"hi kids, do you like violence?",
	"i picked c, ain't that a bitch?",
	"i just drank a fifth of vodka, dare me to drive?",
	"series of tubes",
	"p0laris.dev",
	"Not gonna be active on Discord tonight.",
	"you wouldn't download a fucking car, would you?",
	"tip: of the iceberg",
	"tip: of these nuts",
	"tip: just the",
	"deez",
	"nuts",
	"Ukrain !!!! e,"
	"Shit pants"
	".su"
	"Ala,"
	"IOS 4.1 GEEKGRADE JB REAL!!!"
	"IPHONE 4 CUSTOM IPSW IOS 6.1.7!!"
	"S."
	"tinyurl.com/REALlol11"
	"Frt Nite !!!"
	"ass"
// is this enough
};

char* get_quote(void) {
	/* gotta be secure with this garbage */
	srand((unsigned int)mach_absolute_time());
	
	int len = sizeof(quotes) / sizeof(quotes[0]);
	int index = rand() % len;
	
	return quotes[index];
}

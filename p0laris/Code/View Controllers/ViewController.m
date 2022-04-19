/*
 *  ViewController.m
 *  p0laris
 *
 *  created on 11/19/21
 */

#import  "../Garbage/quote.h"
#import  "ViewController.h"
#include <sys/utsname.h>

#define WITH_CREDITS 0

@interface ViewController ()
@property (weak, nonatomic) IBOutlet UIButton *jb_button;
@property (weak, nonatomic) IBOutlet UILabel *status_label;
@property (weak, nonatomic) IBOutlet UILabel *quote_garbage;

@end

@implementation ViewController

struct offsets_t* offsets;
id param_;

#if WITH_CREDITS
- (IBAction)do_teh_credits:(id)sender {
	[self performSegueWithIdentifier:@"showCredits" sender:self];
}
#endif

-(void)_set_label_text: (char*)s {
	NSString* s_as_NSString = [NSString stringWithUTF8String:s];
	[_status_label setText:s_as_NSString];
	[self.status_label setHidden:false];
	return;
}

void set_label_text(char* s) {
	dispatch_sync(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
		[param_ _set_label_text:s];
	});
}

-(void)_set_button_text: (char*)s {
	NSString* s_as_NSString = [NSString stringWithUTF8String:s];
	[_jb_button setTitle:s_as_NSString forState:UIControlStateNormal];
	[_jb_button setTitle:s_as_NSString forState:UIControlStateDisabled];
	return;
}

void set_button_text(char* s) {
	dispatch_sync(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
	[param_ _set_button_text:s];
	});
}

- (IBAction)do_it:(id)sender {
	[self.jb_button setEnabled:false];
	set_button_text("jailbreaking");

	[self.status_label setHidden:false];

	int go(bool);
	go(false);
}

-(UIStatusBarStyle)preferredStatusBarStyle {
	return UIStatusBarStyleLightContent;
}

/*
 *  no longer used :(
 */
UIAlertController* alert;
UIAlertAction* defaultAction;
- (IBAction)hi_we_ve_been_trying_to_contact_you_about_your_cars_extended_warranty:(id)sender {
	alert = [UIAlertController alertControllerWithTitle:@"Hi, we've been trying to contact you about your car's extended warranty. "
			 message:[NSString stringWithFormat:@"Hi, we've been trying to contact you about your car's extended warranty. Your car's extended warranty is due to expire within 3 weeks, and we are contacting you about your car's extended warranty to inquire if you are interested in getting your car's extended warranty extended. If you want your car's extended warranty to be extended, please call 1-800-420-6969 and say \"I would like to extend my car's extended warranty\" to discuss extending your car's extended warranty, and to possibly actually extend your car's extended warranty in an extendedly extended fashion. Thank you for listening. In all seriousness, I put a lot of work into this jailbreak, enjoy! - spv"]
			 preferredStyle:UIAlertControllerStyleAlert];
     
	defaultAction = [UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault
					 handler:^(UIAlertAction * action) {}];
     
	[alert addAction:defaultAction];
	[self presentViewController:alert animated:YES completion:nil];
}

- (void)viewDidLoad {
	[super viewDidLoad];
	param_ = self;
	[self setNeedsStatusBarAppearanceUpdate];
    
	[_quote_garbage setText:[NSString stringWithUTF8String:get_quote()]];
}

@end

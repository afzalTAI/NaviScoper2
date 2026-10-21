// navi_menu_* install a menu-bar status agent using AppKit. The status item
// sits on the right side of the macOS menu bar; the left side is reserved for
// the foreground application's own menus and cannot host agents.
#import <Cocoa/Cocoa.h>
#import "menu.h"

@interface NaviMenuTarget : NSObject <NSMenuDelegate>
@property (strong) NSStatusItem *statusItem;
@property (strong) NSMenuItem *statusRow;
@property (strong) NSMenuItem *toggleRow;
@property (strong) NSMenuItem *routeRow;
@property (strong) NSMenuItem *openRow;
@end

@implementation NaviMenuTarget

- (void)refresh {
	char buf[256];
	navi_status_text(buf, sizeof buf);
	NSString *text = [NSString stringWithUTF8String:buf];
	if (text == nil) {
		text = @"NaviScope";
	}
	self.statusRow.title = text;
	self.toggleRow.state = navi_enabled() ? NSControlStateValueOn : NSControlStateValueOff;
	self.toggleRow.title = navi_enabled() ? @"Filtering enabled" : @"Filtering paused";
	// Routing applies asynchronously; the checkmark settles on next open.
	self.routeRow.state = navi_route_enabled() ? NSControlStateValueOn : NSControlStateValueOff;
	// Routing applies asynchronously; the checkmark settles on next open.
	self.routeRow.state = navi_route_enabled() ? NSControlStateValueOn : NSControlStateValueOff;
}

- (void)menuWillOpen:(NSMenu *)menu {
	[self refresh];
}

- (void)toggle:(id)sender {
	navi_toggle();
	[self refresh];
}

- (void)toggleRoute:(id)sender {
	navi_route_toggle();
}

- (void)open:(id)sender {
	char buf[256];
	navi_dashboard_url(buf, sizeof buf);
	NSString *text = [NSString stringWithUTF8String:buf];
	if (text.length > 0) {
		[[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:text]];
	}
}

- (void)quit:(id)sender {
	// Go cancels the serve context; navi_menu_stop arrives via AfterFunc.
	navi_quit();
}

@end

static NaviMenuTarget *naviTarget = nil;

void navi_menu_run(void) {
	[NSApplication sharedApplication];
	[NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];

	NSMenu *menu = [[NSMenu alloc] initWithTitle:@"NaviScope"];
	naviTarget = [[NaviMenuTarget alloc] init];

	naviTarget.statusRow = [menu addItemWithTitle:@"NaviScope"
										   action:nil
									keyEquivalent:@""];
	naviTarget.statusRow.enabled = NO;

	naviTarget.toggleRow = [menu addItemWithTitle:@"Filtering enabled"
										   action:@selector(toggle:)
									keyEquivalent:@""];
	naviTarget.toggleRow.target = naviTarget;

	naviTarget.routeRow = [menu addItemWithTitle:@"Route system traffic"
										  action:@selector(toggleRoute:)
								   keyEquivalent:@""];
	naviTarget.routeRow.target = naviTarget;

	char urlBuf[256];
	navi_dashboard_url(urlBuf, sizeof urlBuf);
	naviTarget.openRow = [menu addItemWithTitle:@"Open dashboard…"
										 action:@selector(open:)
								  keyEquivalent:@""];
	naviTarget.openRow.target = naviTarget;
	naviTarget.openRow.hidden = (urlBuf[0] == 0);

	[menu addItem:[NSMenuItem separatorItem]];
	NSMenuItem *quitRow = [menu addItemWithTitle:@"Quit NaviScope"
										  action:@selector(quit:)
								   keyEquivalent:@"q"];
	quitRow.target = naviTarget;
	menu.delegate = naviTarget;

	NSStatusItem *item = [[NSStatusBar systemStatusBar]
		statusItemWithLength:NSVariableStatusItemLength];
	NSImage *icon = [NSImage imageWithSystemSymbolName:@"antenna.radiowaves.left.and.right"
							 accessibilityDescription:@"NaviScope proxy"];
	if (icon != nil) {
		icon.template = YES;
		item.button.image = icon;
	} else {
		item.button.title = @"◈";
	}
	item.menu = menu;
	naviTarget.statusItem = item;

	[NSApp activateIgnoringOtherApps:NO];
	[NSApp run];
}

void navi_menu_stop(void) {
	dispatch_async(dispatch_get_main_queue(), ^{
		[NSApp stop:nil];
		// The run loop may be idle; wake it so stop takes effect promptly.
		NSEvent *wake = [NSEvent
			otherEventWithType:NSEventTypeApplicationDefined
				      location:NSZeroPoint
				 modifierFlags:0
				     timestamp:0
				  windowNumber:0
				       context:nil
				       subtype:0
					 data1:0
					 data2:0];
		if (wake != nil) {
			[NSApp postEvent:wake atStart:YES];
		}
	});
}

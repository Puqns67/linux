/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2014-2020 NXP Semiconductors, All Rights Reserved.
 * Copyright 2021 GOODIX
 */


/** Filename: tfa9878_tfaFieldnames.h
 *	This file was generated automatically on 06/28/19 at 10:22:32.
 *	Source file: TFA9878_PRB3_N1A1_DefaultI2CSettings.xlsx
 */

#ifndef _TFA9878_TFAFIELDNAMES_H
#define _TFA9878_TFAFIELDNAMES_H


#define TFA9878_I2CVERSION	12

enum Tfa9878BfEnumList {
	TFA9878_BF_PWDN	= 0x0000,	/*!< Powerdown selection			                     */
	TFA9878_BF_I2CR	= 0x0010,	/*!< I2C Reset - Auto clear			                  */
	TFA9878_BF_AMPE	= 0x0030,	/*!< Activate Amplifier			                      */
	TFA9878_BF_DCA	= 0x0040,	/*!< Activate DC-to-DC converter			              */
	TFA9878_BF_INTP	= 0x0071,	/*!< Interrupt config			                        */
	TFA9878_BF_FSSSEL= 0x0090,	/*!< Audio sample reference				                */
	TFA9878_BF_BYPOCP= 0x00b0,	/*!< Bypass OCP				                            */
	TFA9878_BF_TSTOCP= 0x00c0,	/*!< OCP testing control				                   */
	TFA9878_BF_AMPINSEL= 0x0101,	/*!< Amplifier input selection				             */
	TFA9878_BF_MANSCONF= 0x0120,	/*!< I2C configured				                        */
	TFA9878_BF_DCINSEL= 0x0131,	/*!< VAMP_OUT2 input selection				             */
	TFA9878_BF_MUTETO= 0x0160,	/*!< Time out SB mute sequence				             */
	TFA9878_BF_MANROBOD= 0x0170,	/*!< Reaction on BOD				                       */
	TFA9878_BF_BODE	= 0x0180,	/*!< Enable BOD (only in direct control mode)			*/
	TFA9878_BF_BODHYS= 0x0190,	/*!< Enable Hysteresis of BOD				              */
	TFA9878_BF_BODFILT= 0x01a1,	/*!< BOD filter				                            */
	TFA9878_BF_BODTHLVL= 0x01c1,	/*!< BOD threshold				                         */
	TFA9878_BF_OPENMTP= 0x01e0,	/*!< Control for FAIM protection				           */
	TFA9878_BF_DISFCRBST= 0x01f0,	/*!< disable	boost control with FRCBST			      */
	TFA9878_BF_AUDFS = 0x0203,	/*!< Sample rate (fs)				                      */
	TFA9878_BF_INPLEV= 0x0240,	/*!< TDM output attenuation				                */
	TFA9878_BF_FRACTDEL= 0x0255,	/*!< V/I Fractional delay				                  */
	TFA9878_BF_AMPINPSEL= 0x02b1,	/*!< amp input selection				                   */
	TFA9878_BF_PDMRATE= 0x02d0,	/*!< Pdm rate				                              */
	TFA9878_BF_REV	= 0x030f,	/*!< Revision info			                            */
	TFA9878_BF_REFCKEXT= 0x0401,	/*!< PLL external ref clock				                */
	TFA9878_BF_REFCKSEL= 0x0420,	/*!< PLL internal ref clock				                */
	TFA9878_BF_SWCLKSEL= 0x0432,	/*!< Sound Wire clock frequnecy				            */
	TFA9878_BF_MANAOOSC= 0x0460,	/*!< Internal osc off at PWDN				              */
	TFA9878_BF_FSSYNCEN= 0x0480,	/*!< Enable FS synchronisation for clock divider		*/
	TFA9878_BF_CLKREFSYNCEN= 0x0490,	/*!< Enable PLL reference clock synchronisation for clock divider */
	TFA9878_BF_AUTOFROSEL= 0x04a0,	/*!< override automatic OSC selection mechanism		 */
	TFA9878_BF_SWFRSYNC= 0x04b0,	/*!< Selection SW signal reference for Stream Synchronization	*/
	TFA9878_BF_CGUSYNCDCG= 0x0500,	/*!< Clock gating control for CGU synchronisation module */
	TFA9878_BF_FRCCLKSPKR= 0x0510,	/*!< force active the speaker sub-system clock when in idle power */
	TFA9878_BF_SSFAIME= 0x05c0,	/*!< Sub-system FAIM				                       */
	TFA9878_BF_CLKCHKLO= 0x0707,	/*!< Clock check Low Threshold				             */
	TFA9878_BF_CLKCHKHI= 0x0787,	/*!< Clock check Higher Threshold				          */
	TFA9878_BF_AMPOCRT= 0x0802,	/*!< Amplifier on-off criteria for shutdown				*/
	TFA9878_BF_VDDS	= 0x1000,	/*!< POR			                                     */
	TFA9878_BF_DCOCPOK= 0x1010,	/*!< DCDC OCP nmos	(sticky register , clear on read)	*/
	TFA9878_BF_OTDS	= 0x1020,	/*!< OTP alarm	(sticky register , clear on read)	  */
	TFA9878_BF_OCDS	= 0x1030,	/*!< OCP  amplifier	(sticky register , clear on read) */
	TFA9878_BF_UVDS	= 0x1040,	/*!< UVP alarm  (sticky register , clear on read)		*/
	TFA9878_BF_MANALARM= 0x1050,	/*!< Alarm state				                           */
	TFA9878_BF_CLKS	= 0x1060,	/*!< Clocks stable			                           */
	TFA9878_BF_MTPB	= 0x1070,	/*!< MTP busy			                                */
	TFA9878_BF_NOCLK = 0x1080,	/*!< Lost clock	(sticky register , clear on read)	  */
	TFA9878_BF_BODNOK= 0x1090,	/*!< BOD Flag - VDD NOT OK				                 */
	TFA9878_BF_TDMERR= 0x10a0,	/*!< TDM error				                             */
	TFA9878_BF_DCIL	= 0x1100,	/*!< DCDC current limiting			                   */
	TFA9878_BF_DCDCA = 0x1110,	/*!< DCDC active	(sticky register , clear on read)	 */
	TFA9878_BF_DCDCPC= 0x1120,	/*!< Indicates current is max in DC-to-DC converter	 */
	TFA9878_BF_DCHVBAT= 0x1130,	/*!< DCDC level 1x				                         */
	TFA9878_BF_DCH114= 0x1140,	/*!< DCDC level 1.14x				                      */
	TFA9878_BF_DCH107= 0x1150,	/*!< DCDC level 1.07x				                      */
	TFA9878_BF_PLLS	= 0x1160,	/*!< PLL lock			                                */
	TFA9878_BF_TDMLUTER= 0x1180,	/*!< TDM LUT error				                         */
	TFA9878_BF_CLKOOR= 0x11c0,	/*!< External clock status				                 */
	TFA9878_BF_SWS	= 0x11d0,	/*!< Amplifier engage			                         */
	TFA9878_BF_AMPS	= 0x11e0,	/*!< Amplifier enable			                        */
	TFA9878_BF_AREFS = 0x11f0,	/*!< References enable				                     */
	TFA9878_BF_OCPOAP= 0x1300,	/*!< OCPOK pmos B				                          */
	TFA9878_BF_OCPOAN= 0x1310,	/*!< OCPOK pmos A				                          */
	TFA9878_BF_OCPOBP= 0x1320,	/*!< OCPOK nmos B				                          */
	TFA9878_BF_OCPOBN= 0x1330,	/*!< OCPOK nmos A				                          */
	TFA9878_BF_OVDS	= 0x1380,	/*!< OVP alarm			                               */
	TFA9878_BF_CLIPS = 0x1390,	/*!< Amplifier	clipping			                     */
	TFA9878_BF_ADCCR = 0x13a0,	/*!< Control ADC				                           */
	TFA9878_BF_MANWAIT1= 0x13c0,	/*!< Wait HW I2C settings				                  */
	TFA9878_BF_MANMUTE= 0x13e0,	/*!< Audio mute sequence				                   */
	TFA9878_BF_MANOPER= 0x13f0,	/*!< Operating state				                       */
	TFA9878_BF_TDMSTAT= 0x1402,	/*!< TDM status bits				                       */
	TFA9878_BF_MANSTATE= 0x1433,	/*!< Device manager status				                 */
	TFA9878_BF_AMPSTE= 0x1473,	/*!< Amplifier control status				              */
	TFA9878_BF_DCMODE= 0x14b1,	/*!< DCDC mode status bits				                 */
	TFA9878_BF_BATS	= 0x1509,	/*!< Battery voltage (V)			                     */
	TFA9878_BF_TEMPS = 0x1608,	/*!< IC Temperature (C)				                    */
	TFA9878_BF_VDDPS = 0x1709,	/*!< IC VDDP voltage ( 1023*VDDP/13 V)				     */
	TFA9878_BF_TDME	= 0x2000,	/*!< Enable interface			                        */
	TFA9878_BF_TDMSLOTS= 0x2013,	/*!< N-slots in Frame				                      */
	TFA9878_BF_TDMCLINV= 0x2060,	/*!< Reception data to BCK clock				           */
	TFA9878_BF_TDMFSLN= 0x2073,	/*!< FS length				                             */
	TFA9878_BF_TDMFSPOL= 0x20b0,	/*!< FS polarity				                           */
	TFA9878_BF_TDMNBCK= 0x20c3,	/*!< N-BCK's in FS				                         */
	TFA9878_BF_TDMSLLN= 0x2144,	/*!< N-bits in slot				                        */
	TFA9878_BF_TDMBRMG= 0x2194,	/*!< N-bits remaining				                      */
	TFA9878_BF_TDMDEL= 0x21e0,	/*!< data delay to FS				                      */
	TFA9878_BF_TDMADJ= 0x21f0,	/*!< data adjustment				                       */
	TFA9878_BF_TDMOOMP= 0x2201,	/*!< Received audio compression				            */
	TFA9878_BF_TDMSSIZE= 0x2224,	/*!< Sample size per slot				                  */
	TFA9878_BF_TDMTXDFO= 0x2271,	/*!< Format unused bits				                    */
	TFA9878_BF_TDMTXUS0= 0x2291,	/*!< Format unused slots DATAO				             */
	TFA9878_BF_TDMSPKE= 0x2300,	/*!< Control audio tdm channel in 0				        */
	TFA9878_BF_TDMDCE= 0x2310,	/*!< Control audio	tdm channel in 1			         */
	TFA9878_BF_TDMCSE= 0x2330,	/*!< current sense vbat temperature and vddp feedback	*/
	TFA9878_BF_TDMVSE= 0x2340,	/*!< Voltage sense vbat temperature and vddp feedback	*/
	TFA9878_BF_TDMSPKS= 0x2603,	/*!< tdm slot for sink 0				                   */
	TFA9878_BF_TDMDCS= 0x2643,	/*!< tdm slot for	sink 1			                    */
	TFA9878_BF_TDMCSS= 0x26c3,	/*!< Slot Position of current sense vbat temperature and vddp feedback */
	TFA9878_BF_TDMVSS= 0x2703,	/*!< Slot Position of Voltage sense vbat temperature and vddp feedback */
	TFA9878_BF_ISTVDDS= 0x4000,	/*!< Status POR				                            */
	TFA9878_BF_ISTBSTOC= 0x4010,	/*!< Status DCDC OCP				                       */
	TFA9878_BF_ISTOTDS= 0x4020,	/*!< Status OTP alarm				                      */
	TFA9878_BF_ISTOCPR= 0x4030,	/*!< Status ocp alarm				                      */
	TFA9878_BF_ISTUVDS= 0x4040,	/*!< Status UVP alarm				                      */
	TFA9878_BF_ISTMANALARM= 0x4050,	/*!< Status	nanager Alarm state			             */
	TFA9878_BF_ISTTDMER= 0x4060,	/*!< Status tdm error				                      */
	TFA9878_BF_ISTNOCLK= 0x4070,	/*!< Status lost clock				                     */
	TFA9878_BF_ISTBODNOK= 0x4080,	/*!< Status BOD event				                      */
	TFA9878_BF_ICLVDDS= 0x4400,	/*!< Clear POR				                             */
	TFA9878_BF_ICLBSTOC= 0x4410,	/*!< Clear DCDC OCP				                        */
	TFA9878_BF_ICLOTDS= 0x4420,	/*!< Clear OTP alarm				                       */
	TFA9878_BF_ICLOCPR= 0x4430,	/*!< Clear ocp alarm				                       */
	TFA9878_BF_ICLUVDS= 0x4440,	/*!< Clear UVP alarm				                       */
	TFA9878_BF_ICLMANALARM= 0x4450,	/*!< Clear	manager Alarm state			              */
	TFA9878_BF_ICLTDMER= 0x4460,	/*!< Clear tdm error				                       */
	TFA9878_BF_ICLNOCLK= 0x4470,	/*!< Clear lost clk				                        */
	TFA9878_BF_ICLBODNOK= 0x4480,	/*!< Clear BOD event				                       */
	TFA9878_BF_IEVDDS= 0x4800,	/*!< Enable por				                            */
	TFA9878_BF_IEBSTOC= 0x4810,	/*!< Enable DCDC OCP				                       */
	TFA9878_BF_IEOTDS= 0x4820,	/*!< Enable OTP alarm				                      */
	TFA9878_BF_IEOCPR= 0x4830,	/*!< Enable ocp alarm				                      */
	TFA9878_BF_IEUVDS= 0x4840,	/*!< Enable UVP alarm				                      */
	TFA9878_BF_IEMANALARM= 0x4850,	/*!< Enable	nanager Alarm state			             */
	TFA9878_BF_IETDMER= 0x4860,	/*!< Enable tdm error				                      */
	TFA9878_BF_IENOCLK= 0x4870,	/*!< Enable lost clk				                       */
	TFA9878_BF_IEBODNOK= 0x4880,	/*!< Enable BOD trigger				                    */
	TFA9878_BF_IPOVDDS= 0x4c00,	/*!< Polarity por				                          */
	TFA9878_BF_IPOBSTOC= 0x4c10,	/*!< Polarity DCDC OCP				                     */
	TFA9878_BF_IPOOTDS= 0x4c20,	/*!< Polarity OTP alarm				                    */
	TFA9878_BF_IPOOCPR= 0x4c30,	/*!< Polarity ocp alarm				                    */
	TFA9878_BF_IPOUVDS= 0x4c40,	/*!< Polarity UVP alarm				                    */
	TFA9878_BF_IPOMANALARM= 0x4c50,	/*!< Polarity	nanager Alarm state			           */
	TFA9878_BF_IPOTDMER= 0x4c60,	/*!< Polarity tdm error				                    */
	TFA9878_BF_IPONOCLK= 0x4c70,	/*!< Polarity lost clk				                     */
	TFA9878_BF_IPOBODNOK= 0x4c80,	/*!< Polarity BOD trigger				                  */
	TFA9878_BF_BSSCR = 0x5001,	/*!< Battery Safeguard attack time (with K = 1 at sample rate fs of 32kHz, 44, 1 kHz or 48kHz ; with K = 2 at sample rate fs 16 kHz . With K	=0.5 at sample rate of 96 kHz) */
	TFA9878_BF_BSST	= 0x5023,	/*!< Battery Safeguard threshold voltage level		  */
	TFA9878_BF_BSSRL = 0x5061,	/*!< Battery Safeguard maximum reduction				   */
	TFA9878_BF_BSSR	= 0x50e0,	/*!< Battery voltage read out			                */
	TFA9878_BF_BSSBY = 0x50f0,	/*!< Bypass battery safeguard				              */
	TFA9878_BF_BSSS	= 0x5100,	/*!< Vbat prot steepness			                     */
	TFA9878_BF_HPFBYP= 0x5150,	/*!< Bypass HPF				                            */
	TFA9878_BF_DPSA	= 0x5170,	/*!< Enable DPSA			                             */
	TFA9878_BF_CLIPCTRL= 0x5222,	/*!< Clip control setting				                  */
	TFA9878_BF_AMPGAIN= 0x5257,	/*!< Amplifier gain				                        */
	TFA9878_BF_SLOPEE= 0x52d0,	/*!< Enables slope control				                 */
	TFA9878_BF_SLOPESET= 0x52e0,	/*!< Slope speed setting (bin. coded)				      */
	TFA9878_BF_BYPDLYLINE= 0x52f0,	/*!< Bypass the interpolator delay line				    */
	TFA9878_BF_TDMDCG= 0x5f23,	/*!< Second channel gain in case of stereo using a single coil. (Total gain depending on INPLEV). (In case of mono OR stereo using 2 separate DCDC channel 1 should be disabled using TDMDCE) */
	TFA9878_BF_TDMSPKG= 0x5f63,	/*!< Total gain depending on INPLEV setting (channel 0) */
	TFA9878_BF_IPM	= 0x60e1,	/*!< Idle power mode control			                  */
	TFA9878_BF_LNMODE= 0x62e1,	/*!< ctrl select mode				                      */
	TFA9878_BF_LPM1MODE= 0x64e1,	/*!< low power mode control				                */
	TFA9878_BF_TDMSRCMAP= 0x6802,	/*!< tdm source mapping				                    */
	TFA9878_BF_TDMSRCAS= 0x6831,	/*!< Sensed value	A			                         */
	TFA9878_BF_TDMSRCBS= 0x6851,	/*!< Sensed value	B			                         */
	TFA9878_BF_TDMSRCACLIP= 0x6871,	/*!< clip information	(analog /digital) for source0	*/
	TFA9878_BF_TDMSRCBCLIP= 0x6891,	/*!< clip information	(analog /digital) for source1	*/
	TFA9878_BF_LP0	= 0x6e00,	/*!< Idle power mode			                          */
	TFA9878_BF_LP1	= 0x6e10,	/*!< low power mode 1 detection			               */
	TFA9878_BF_LA	= 0x6e20,	/*!< low amplitude detection			                   */
	TFA9878_BF_VDDPH = 0x6e30,	/*!< vddp greater than vbat				                */
	TFA9878_BF_DELCURCOMP= 0x6f02,	/*!< delay to align compensation signal with current sense signal */
	TFA9878_BF_SIGCURCOMP= 0x6f40,	/*!< polarity of compensation for current sense		 */
	TFA9878_BF_ENCURCOMP= 0x6f50,	/*!< enable current sense compensation				     */
	TFA9878_BF_LVLCLPPWM= 0x6f72,	/*!< set the amount of pwm pulse that may be skipped before clip-flag is triggered */
	TFA9878_BF_DCMCC = 0x7003,	/*!< Max coil current				                      */
	TFA9878_BF_DCCV	= 0x7041,	/*!< Slope compensation current, represents LxF (inductance x frequency) value  */
	TFA9878_BF_DCIE	= 0x7060,	/*!< Adaptive boost mode			                     */
	TFA9878_BF_DCSR	= 0x7070,	/*!< Soft ramp up/down			                       */
	TFA9878_BF_DCOVL = 0x7085,	/*!< Threshold level to activate active overshoot control */
	TFA9878_BF_DCDIS = 0x70e0,	/*!< DCDC on/off				                           */
	TFA9878_BF_DCPWM = 0x70f0,	/*!< DCDC PWM only mode				                    */
	TFA9878_BF_DCTRACK= 0x7430,	/*!< Boost algorithm selection, effective only when boost_intelligent is set to 1 */
	TFA9878_BF_DCTRIP= 0x7444,	/*!< 1st Adaptive boost trip levels, effective only when DCIE is set to 1 */
	TFA9878_BF_DCHOLD= 0x7494,	/*!< Hold time for DCDC booster, effective only when boost_intelligent is set to 1 */
	TFA9878_BF_DCINT = 0x74e0,	/*!< Selection of data for adaptive boost algorithm, effective only when boost_intelligent is set to 1 */
	TFA9878_BF_DCTRIP2= 0x7534,	/*!< 2nd Adaptive boost trip levels, effective only when DCIE is set to 1 */
	TFA9878_BF_DCTRIPT= 0x7584,	/*!< Track Adaptive boost trip levels, effective only when boost_intelligent is set to 1 */
	TFA9878_BF_DCTRIPHYSTE= 0x75f0,	/*!< Enable hysteresis on booster trip levels			*/
	TFA9878_BF_DCVOF = 0x7635,	/*!< First boost voltage level				             */
	TFA9878_BF_DCVOS = 0x7695,	/*!< Second boost voltage level				            */
	TFA9878_BF_MTPK	= 0xa107,	/*!< MTP KEY2 register			                       */
	TFA9878_BF_KEY1LOCKED= 0xa200,	/*!< Indicates KEY1 is locked				              */
	TFA9878_BF_KEY2LOCKED= 0xa210,	/*!< Indicates KEY2 is locked				              */
	TFA9878_BF_MTPADDR= 0xa302,	/*!< MTP address from I2C register for read/writing mtp in manual single word mode */
	TFA9878_BF_MTPRDMSB= 0xa50f,	/*!< MSB word of MTP manual read data				      */
	TFA9878_BF_MTPRDLSB= 0xa60f,	/*!< LSB word of MTP manual read data				      */
	TFA9878_BF_MTPWRMSB= 0xa70f,	/*!< MSB word of write data for MTP manual write		*/
	TFA9878_BF_MTPWRLSB= 0xa80f,	/*!< LSB word of write data for MTP manual write		*/
	TFA9878_BF_EXTTS = 0xb108,	/*!< External temperature (C)				              */
	TFA9878_BF_TROS	= 0xb190,	/*!< Select temp Speaker calibration			         */
	TFA9878_BF_PLLINSI= 0xcd05,	/*!< PLL INSELI - PLL direct bandwidth control mode only with pll_bandsel set to 1 */
	TFA9878_BF_PLLINSP= 0xcd64,	/*!< PLL INSELP - PLL direct bandwidth control mode only with pll_bandsel set to 1 */
	TFA9878_BF_PLLINSR= 0xcdb3,	/*!< PLL INSELR - PLL direct bandwidth control mode only with pll_bandsel set to 1 */
	TFA9878_BF_PLLBDSEL= 0xcdf0,	/*!< PLL bandwidth selection control, USE WITH CAUTION	*/
	TFA9878_BF_PLLNDEC= 0xce09,	/*!< PLL NDEC in direct control mode only, use_direct_pll_ctrl set to 1 */
	TFA9878_BF_PLLMDECM= 0xcea0,	/*!< MSB of PLL MDEC in direct control mode only, use_direct_pll_ctrl set to 1 */
	TFA9878_BF_PLLBP = 0xceb0,	/*!< PLL bypass control during functional mode			*/
	TFA9878_BF_PLLDI = 0xcec0,	/*!< PLL directi control in direct control mode only, use_direct_pll_ctrl set to 1 */
	TFA9878_BF_PLLDO = 0xced0,	/*!< PLL directo control in direct control mode only, use_direct_pll_ctrl set to 1 */
	TFA9878_BF_PLLCLKSTB= 0xcee0,	/*!< PLL FRM clock stable control in direct control mode only, use_direct_pll_ctrl set to 1 */
	TFA9878_BF_PLLFRM= 0xcef0,	/*!< PLL free running mode control in functional mode	*/
	TFA9878_BF_PLLMDECL= 0xcf0f,	/*!< Bits 15..0 of PLL MDEC in direct control mode only, use_direct_pll_ctrl set to 1 */
	TFA9878_BF_PLLPDEC= 0xd006,	/*!< PLL PDEC in direct control mode only, use_direct_pll_ctrl set to 1 */
	TFA9878_BF_PLLDCTRL= 0xd070,	/*!< Enabled PLL direct control mode, overrules the PLL LUT with I2C register values */
	TFA9878_BF_PLLLIMOFF= 0xd090,	/*!< PLL up limiter control in PLL direct bandwidth control mode, pll_bandsel set to 1 */
	TFA9878_BF_PLLSTRTM= 0xd0a2,	/*!< PLL startup time selection control				    */
	TFA9878_BF_SWPROFIL= 0xe00f,	/*!< Software profile data				                 */
	TFA9878_BF_SWVSTEP= 0xe10f,	/*!< Software vstep information				            */
	TFA9878_BF_MTPOTC= 0xf000,	/*!< Calibration schedule				                  */
	TFA9878_BF_MTPEX = 0xf010,	/*!< Calibration Ron executed				              */
	TFA9878_BF_DCMCCAPI= 0xf020,	/*!< Calibration current limit DCDC				        */
	TFA9878_BF_DCMCCSB= 0xf030,	/*!< Sign bit for delta calibration current limit DCDC	*/
	TFA9878_BF_USERDEF= 0xf042,	/*!< Calibration delta current limit DCDC				  */
	TFA9878_BF_CUSTINFO= 0xf078,	/*!< Reserved space for allowing customer to store speaker information */
	TFA9878_BF_R25C	= 0xf50f,	/*!< Ron resistance of  speaker coil			         */
};

enum tfa9878_irq {
	tfa9878_irq_stvdds = 0,
	tfa9878_irq_stbstoc = 1,
	tfa9878_irq_stotds = 2,
	tfa9878_irq_stocpr = 3,
	tfa9878_irq_stuvds = 4,
	tfa9878_irq_stmanalarm = 5,
	tfa9878_irq_sttdmer = 6,
	tfa9878_irq_stnoclk = 7,
	tfa9878_irq_stbodnok = 8,
	tfa9878_irq_max = 9,
	tfa9878_irq_all = -1 /* all irqs */};

#endif

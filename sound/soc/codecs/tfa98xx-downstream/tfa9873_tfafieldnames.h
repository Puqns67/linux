/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2014-2020 NXP Semiconductors, All Rights Reserved.
 * Copyright 2021 GOODIX
 */


/** Filename: tfa9873_tfaFieldnames.h
 *	This file was generated automatically on 10/21/19 at 17:03:34.
 *	Source file: TFA9873_PRB4_N1A0_I2C_RegisterMap.xlsx
 */

#ifndef _TFA9873_TFAFIELDNAMES_H
#define _TFA9873_TFAFIELDNAMES_H


#define TFA9873_I2CVERSION	28

enum Tfa9873BfEnumList {
	TFA9873_BF_PWDN	= 0x0000,	/*!< Powerdown selection			                     */
	TFA9873_BF_I2CR	= 0x0010,	/*!< I2C reset - auto clear			                  */
	TFA9873_BF_AMPE	= 0x0030,	/*!< Activate amplifier			                      */
	TFA9873_BF_DCA	= 0x0040,	/*!< Activate DC-to-DC converter			              */
	TFA9873_BF_INTP	= 0x0071,	/*!< Interrupt config			                        */
	TFA9873_BF_FSSSEL= 0x0090,	/*!< Audio sample reference				                */
	TFA9873_BF_BYPOCP= 0x00b0,	/*!< Bypass OCP				                            */
	TFA9873_BF_TSTOCP= 0x00c0,	/*!< OCP testing control				                   */
	TFA9873_BF_ENPLLSYNC= 0x00e0,	/*!< Manager control for enabling synchronisation with PLL FS */
	TFA9873_BF_AMPINSEL= 0x0101,	/*!< Amplifier input selection				             */
	TFA9873_BF_MANSCONF= 0x0120,	/*!< I2C configured				                        */
	TFA9873_BF_MUTETO= 0x0160,	/*!< Time out SB mute sequence				             */
	TFA9873_BF_OPENMTP= 0x01e0,	/*!< Control for FAIM protection				           */
	TFA9873_BF_DISFCRBST= 0x01f0,	/*!< Disable boost control with FRCBST				     */
	TFA9873_BF_AUDFS = 0x0203,	/*!< Sample rate (fs)				                      */
	TFA9873_BF_INPLEV= 0x0240,	/*!< TDM output attenuation				                */
	TFA9873_BF_FRACTDEL= 0x0255,	/*!< V/I Fractional delay				                  */
	TFA9873_BF_REV	= 0x030f,	/*!< Device revision information			              */
	TFA9873_BF_REFCKEXT= 0x0401,	/*!< PLL external ref clock				                */
	TFA9873_BF_REFCKSEL= 0x0420,	/*!< PLL internal ref clock				                */
	TFA9873_BF_MANAOOSC= 0x0460,	/*!< Internal osc off in power down mode				   */
	TFA9873_BF_FSSYNCEN= 0x0480,	/*!< Enable FS synchronisation for clock divider		*/
	TFA9873_BF_CLKREFSYNCEN= 0x0490,	/*!< Enable PLL reference clock synchronisation for clock divider */
	TFA9873_BF_AUTOFROSEL= 0x04a0,	/*!< Override automatic OSC selection mechanism		 */
	TFA9873_BF_CGUSYNCDCG= 0x0500,	/*!< Clock gating control for CGU synchronisation module */
	TFA9873_BF_FRCCLKSPKR= 0x0510,	/*!< Force active the speaker sub-system clock when in idle power */
	TFA9873_BF_BSTCLKLP= 0x0520,	/*!< Boost clock control in low power mode1				*/
	TFA9873_BF_SSFAIME= 0x05c0,	/*!< Sub-system FAIM				                       */
	TFA9873_BF_CLKCHKLO= 0x0707,	/*!< Clock check low threshold				             */
	TFA9873_BF_CLKCHKHI= 0x0787,	/*!< Clock check higher threshold				          */
	TFA9873_BF_AMPOCRT= 0x0802,	/*!< Amplifier on-off criteria for shutdown				*/
	TFA9873_BF_VDDS	= 0x1000,	/*!< POR			                                     */
	TFA9873_BF_DCOCPOK= 0x1010,	/*!< DCDC OCP nmos (sticky register, clear on read)	 */
	TFA9873_BF_OTDS	= 0x1020,	/*!< OTP alarm (sticky register, clear on read)		 */
	TFA9873_BF_OCDS	= 0x1030,	/*!< OCP amplifier (sticky register, clear on read)	 */
	TFA9873_BF_UVDS	= 0x1040,	/*!< UVP alarm (sticky register, clear on read)		 */
	TFA9873_BF_MANALARM= 0x1050,	/*!< Alarm state				                           */
	TFA9873_BF_CLKS	= 0x1060,	/*!< Clocks stable			                           */
	TFA9873_BF_MTPB	= 0x1070,	/*!< MTP busy			                                */
	TFA9873_BF_NOCLK = 0x1080,	/*!< Lost clock (sticky register, clear on read)		*/
	TFA9873_BF_TDMERR= 0x10a0,	/*!< TDM error				                             */
	TFA9873_BF_DCIL	= 0x1100,	/*!< DCDC current limiting			                   */
	TFA9873_BF_DCDCA = 0x1110,	/*!< DCDC active (sticky register, clear on read)		*/
	TFA9873_BF_DCDCPC= 0x1120,	/*!< Indicates current is max in DC-to-DC converter	 */
	TFA9873_BF_DCHVBAT= 0x1130,	/*!< DCDC level 1x				                         */
	TFA9873_BF_DCH114= 0x1140,	/*!< DCDC level 1.14x				                      */
	TFA9873_BF_DCH107= 0x1150,	/*!< DCDC level 1.07x				                      */
	TFA9873_BF_PLLS	= 0x1160,	/*!< PLL lock			                                */
	TFA9873_BF_TDMLUTER= 0x1180,	/*!< TDM LUT error				                         */
	TFA9873_BF_CLKOOR= 0x11c0,	/*!< External clock status				                 */
	TFA9873_BF_SWS	= 0x11d0,	/*!< Amplifier engage			                         */
	TFA9873_BF_AMPS	= 0x11e0,	/*!< Amplifier enable			                        */
	TFA9873_BF_AREFS = 0x11f0,	/*!< References enable				                     */
	TFA9873_BF_OCPOAP= 0x1300,	/*!< OCPOK pmos A				                          */
	TFA9873_BF_OCPOAN= 0x1310,	/*!< OCPOK nmos A				                          */
	TFA9873_BF_OCPOBP= 0x1320,	/*!< OCPOK pmos B				                          */
	TFA9873_BF_OCPOBN= 0x1330,	/*!< OCPOK nmos B				                          */
	TFA9873_BF_OVDS	= 0x1380,	/*!< OVP alarm			                               */
	TFA9873_BF_CLIPS = 0x1390,	/*!< Amplifier clipping				                    */
	TFA9873_BF_ADCCR = 0x13a0,	/*!< Control ADC				                           */
	TFA9873_BF_MANWAIT1= 0x13c0,	/*!< Wait HW I2C settings				                  */
	TFA9873_BF_MANMUTE= 0x13e0,	/*!< Audio mute sequence				                   */
	TFA9873_BF_MANOPER= 0x13f0,	/*!< Operating state				                       */
	TFA9873_BF_TDMSTAT= 0x1402,	/*!< TDM status bits				                       */
	TFA9873_BF_MANSTATE= 0x1433,	/*!< Device manager status				                 */
	TFA9873_BF_AMPSTE= 0x1473,	/*!< Amplifier control status				              */
	TFA9873_BF_DCMODE= 0x14b1,	/*!< DCDC mode status bits				                 */
	TFA9873_BF_WAITSYNC= 0x14d0,	/*!< CGU and PLL synchronisation status flag from CGU	*/
	TFA9873_BF_BATS	= 0x1509,	/*!< Battery voltage (V)			                     */
	TFA9873_BF_TEMPS = 0x1608,	/*!< IC Temperature (C)				                    */
	TFA9873_BF_VDDPS = 0x1709,	/*!< IC VDDP voltage ( 1023*VDDP/13 V)				     */
	TFA9873_BF_TDME	= 0x2000,	/*!< Enable interface			                        */
	TFA9873_BF_TDMSLOTS= 0x2013,	/*!< N-slots in Frame				                      */
	TFA9873_BF_TDMCLINV= 0x2060,	/*!< Reception data to BCK clock				           */
	TFA9873_BF_TDMFSLN= 0x2073,	/*!< FS length				                             */
	TFA9873_BF_TDMFSPOL= 0x20b0,	/*!< FS polarity				                           */
	TFA9873_BF_TDMNBCK= 0x20c3,	/*!< N-BCK's in FS				                         */
	TFA9873_BF_TDMSLLN= 0x2144,	/*!< N-bits in slot				                        */
	TFA9873_BF_TDMBRMG= 0x2194,	/*!< N-bits remaining				                      */
	TFA9873_BF_TDMDEL= 0x21e0,	/*!< Data delay to FS				                      */
	TFA9873_BF_TDMADJ= 0x21f0,	/*!< Data adjustment				                       */
	TFA9873_BF_TDMOOMP= 0x2201,	/*!< Received audio compression				            */
	TFA9873_BF_TDMSSIZE= 0x2224,	/*!< Sample size per slot				                  */
	TFA9873_BF_TDMTXDFO= 0x2271,	/*!< Format unused bits				                    */
	TFA9873_BF_TDMTXUS0= 0x2291,	/*!< Format unused slots DATAO				             */
	TFA9873_BF_TDMSPKE= 0x2300,	/*!< Control audio TDM channel in 0				        */
	TFA9873_BF_TDMDCE= 0x2310,	/*!< Control audio TDM channel in 1				        */
	TFA9873_BF_TDMCSE= 0x2330,	/*!< current sense vbat temperature and vddp feedback	*/
	TFA9873_BF_TDMVSE= 0x2340,	/*!< Voltage sense vbat temperature and vddp feedback	*/
	TFA9873_BF_TDMSPKS= 0x2603,	/*!< TDM slot for sink 0				                   */
	TFA9873_BF_TDMDCS= 0x2643,	/*!< TDM slot for sink 1				                   */
	TFA9873_BF_TDMCSS= 0x26c3,	/*!< Slot Position of current sense vbat temperature and vddp feedback */
	TFA9873_BF_TDMVSS= 0x2703,	/*!< Slot Position of Voltage sense vbat temperature and vddp feedback */
	TFA9873_BF_ISTVDDS= 0x4000,	/*!< Status POR				                            */
	TFA9873_BF_ISTBSTOC= 0x4010,	/*!< Status DCDC OCP				                       */
	TFA9873_BF_ISTOTDS= 0x4020,	/*!< Status OTP alarm				                      */
	TFA9873_BF_ISTOCPR= 0x4030,	/*!< Status OCP alarm				                      */
	TFA9873_BF_ISTUVDS= 0x4040,	/*!< Status UVP alarm				                      */
	TFA9873_BF_ISTMANALARM= 0x4050,	/*!< Status manager alarm state				            */
	TFA9873_BF_ISTTDMER= 0x4060,	/*!< Status TDM error				                      */
	TFA9873_BF_ISTNOCLK= 0x4070,	/*!< Status lost clock				                     */
	TFA9873_BF_ICLVDDS= 0x4400,	/*!< Clear POR				                             */
	TFA9873_BF_ICLBSTOC= 0x4410,	/*!< Clear DCDC OCP				                        */
	TFA9873_BF_ICLOTDS= 0x4420,	/*!< Clear OTP alarm				                       */
	TFA9873_BF_ICLOCPR= 0x4430,	/*!< Clear OCP alarm				                       */
	TFA9873_BF_ICLUVDS= 0x4440,	/*!< Clear UVP alarm				                       */
	TFA9873_BF_ICLMANALARM= 0x4450,	/*!< Clear manager alarm state				             */
	TFA9873_BF_ICLTDMER= 0x4460,	/*!< Clear TDM error				                       */
	TFA9873_BF_ICLNOCLK= 0x4470,	/*!< Clear lost clk				                        */
	TFA9873_BF_IEVDDS= 0x4800,	/*!< Enable POR				                            */
	TFA9873_BF_IEBSTOC= 0x4810,	/*!< Enable DCDC OCP				                       */
	TFA9873_BF_IEOTDS= 0x4820,	/*!< Enable OTP alarm				                      */
	TFA9873_BF_IEOCPR= 0x4830,	/*!< Enable OCP alarm				                      */
	TFA9873_BF_IEUVDS= 0x4840,	/*!< Enable UVP alarm				                      */
	TFA9873_BF_IEMANALARM= 0x4850,	/*!< Enable manager alarm state				            */
	TFA9873_BF_IETDMER= 0x4860,	/*!< Enable TDM error				                      */
	TFA9873_BF_IENOCLK= 0x4870,	/*!< Enable lost clk				                       */
	TFA9873_BF_IPOVDDS= 0x4c00,	/*!< Polarity POR				                          */
	TFA9873_BF_IPOBSTOC= 0x4c10,	/*!< Polarity DCDC OCP				                     */
	TFA9873_BF_IPOOTDS= 0x4c20,	/*!< Polarity OTP alarm				                    */
	TFA9873_BF_IPOOCPR= 0x4c30,	/*!< Polarity OCP alarm				                    */
	TFA9873_BF_IPOUVDS= 0x4c40,	/*!< Polarity UVP alarm				                    */
	TFA9873_BF_IPOMANALARM= 0x4c50,	/*!< Polarity manager alarm state				          */
	TFA9873_BF_IPOTDMER= 0x4c60,	/*!< Polarity TDM error				                    */
	TFA9873_BF_IPONOCLK= 0x4c70,	/*!< Polarity lost clk				                     */
	TFA9873_BF_BSSCR = 0x5001,	/*!< Battery safeguard attack time				         */
	TFA9873_BF_BSST	= 0x5023,	/*!< Battery safeguard threshold voltage level		  */
	TFA9873_BF_BSSRL = 0x5061,	/*!< Battery safeguard maximum reduction				   */
	TFA9873_BF_BSSR	= 0x50e0,	/*!< Battery voltage read out			                */
	TFA9873_BF_BSSBY = 0x50f0,	/*!< Bypass battery safeguard				              */
	TFA9873_BF_BSSS	= 0x5100,	/*!< Vbat prot steepness			                     */
	TFA9873_BF_HPFBYP= 0x5150,	/*!< Bypass HPF				                            */
	TFA9873_BF_DPSA	= 0x5170,	/*!< Enable DPSA			                             */
	TFA9873_BF_BYHWCLIP= 0x5240,	/*!< Bypass hardware clipper				               */
	TFA9873_BF_AMPGAIN= 0x5257,	/*!< Amplifier gain				                        */
	TFA9873_BF_SLOPEE= 0x52d0,	/*!< Enables slope control				                 */
	TFA9873_BF_SLOPESET= 0x52e0,	/*!< Slope speed setting (bin. coded)				      */
	TFA9873_BF_BYPDLYLINE= 0x52f0,	/*!< Bypass the interpolator delay line				    */
	TFA9873_BF_TDMSPKG= 0x5f63,	/*!< Total gain depending on INPLEV setting (channel 0) */
	TFA9873_BF_IPM	= 0x60e1,	/*!< Idle power mode control			                  */
	TFA9873_BF_LNMODE= 0x62e1,	/*!< Ctrl select mode				                      */
	TFA9873_BF_LPM1MODE= 0x64e1,	/*!< Low power mode control				                */
	TFA9873_BF_TDMSRCMAP= 0x6802,	/*!< TDM source mapping				                    */
	TFA9873_BF_TDMSRCAS= 0x6831,	/*!< Sensed value A				                        */
	TFA9873_BF_TDMSRCBS= 0x6851,	/*!< Sensed value B				                        */
	TFA9873_BF_TDMSRCACLIP= 0x6871,	/*!< Clip information (analog /digital) for source0	 */
	TFA9873_BF_TDMSRCBCLIP= 0x6891,	/*!< Clip information (analog /digital) for source1	 */
	TFA9873_BF_LP0	= 0x6e00,	/*!< Idle power mode			                          */
	TFA9873_BF_LP1	= 0x6e10,	/*!< Low power mode 1 detection			               */
	TFA9873_BF_LA	= 0x6e20,	/*!< Low amplitude detection			                   */
	TFA9873_BF_VDDPH = 0x6e30,	/*!< Vddp greater than Vbat				                */
	TFA9873_BF_DELCURCOMP= 0x6f02,	/*!< Delay to align compensation signal with current sense signal */
	TFA9873_BF_SIGCURCOMP= 0x6f40,	/*!< Polarity of compensation for current sense		 */
	TFA9873_BF_ENCURCOMP= 0x6f50,	/*!< Enable current sense compensation				     */
	TFA9873_BF_LVLCLPPWM= 0x6f72,	/*!< Set the amount of pwm pulse that may be skipped before clip-flag is triggered */
	TFA9873_BF_DCMCC = 0x7003,	/*!< Max coil current				                      */
	TFA9873_BF_DCCV	= 0x7041,	/*!< Slope compensation current, represents LxF (inductance x frequency)  */
	TFA9873_BF_DCIE	= 0x7060,	/*!< Adaptive boost mode			                     */
	TFA9873_BF_DCSR	= 0x7070,	/*!< Soft ramp up/down			                       */
	TFA9873_BF_DCOVL = 0x7085,	/*!< Threshold level to activate active overshoot control */
	TFA9873_BF_DCDIS = 0x70e0,	/*!< DCDC on/off				                           */
	TFA9873_BF_DCPWM = 0x70f0,	/*!< DCDC PWM only mode				                    */
	TFA9873_BF_DCDYFSW= 0x7420,	/*!< Disables the dynamic frequency switching due to flag_voutcomp86/93 */
	TFA9873_BF_DCTRACK= 0x7430,	/*!< Boost algorithm selection, effective only when boost_intelligent is set to 1 */
	TFA9873_BF_DCTRIP= 0x7444,	/*!< 1st Adaptive boost trip levels, effective only when DCIE is set to 1 */
	TFA9873_BF_DCHOLD= 0x7494,	/*!< Hold time for DCDC booster, effective only when boost_intelligent is set to 1 */
	TFA9873_BF_DCINT = 0x74e0,	/*!< Selection of data for adaptive boost algorithm, effective only when boost_intelligent is set to 1 */
	TFA9873_BF_DCTRIP2= 0x7534,	/*!< 2nd Adaptive boost trip levels, effective only when DCIE is set to 1 */
	TFA9873_BF_DCTRIPT= 0x7584,	/*!< Track Adaptive boost trip levels, effective only when boost_intelligent is set to 1 */
	TFA9873_BF_DCTRIPHYSTE= 0x75f0,	/*!< Enable hysteresis on booster trip levels			*/
	TFA9873_BF_ENBSTFLT= 0x7620,	/*!< Enable the boost filter				               */
	TFA9873_BF_DCVOF = 0x7635,	/*!< First boost voltage level				             */
	TFA9873_BF_DCVOS = 0x7695,	/*!< Second boost voltage level				            */
	TFA9873_BF_MTPK	= 0xa107,	/*!< MTP KEY2 register			                       */
	TFA9873_BF_KEY1LOCKED= 0xa200,	/*!< Indicates KEY1 is locked				              */
	TFA9873_BF_KEY2LOCKED= 0xa210,	/*!< Indicates KEY2 is locked				              */
	TFA9873_BF_MTPADDR= 0xa302,	/*!< MTP address from I2C register for read/writing mtp in manual single word mode */
	TFA9873_BF_MTPRDMSB= 0xa50f,	/*!< MSB word of MTP manual read data				      */
	TFA9873_BF_MTPRDLSB= 0xa60f,	/*!< LSB word of MTP manual read data				      */
	TFA9873_BF_MTPWRMSB= 0xa70f,	/*!< MSB word of write data for MTP manual write		*/
	TFA9873_BF_MTPWRLSB= 0xa80f,	/*!< LSB word of write data for MTP manual write		*/
	TFA9873_BF_EXTTS = 0xb108,	/*!< External temperature (C)				              */
	TFA9873_BF_TROS	= 0xb190,	/*!< Select temp Speaker calibration			         */
	TFA9873_BF_PLLINSI= 0xcd05,	/*!< PLL INSELI - PLL direct bandwidth control mode, only with pll_bandsel set to 1 */
	TFA9873_BF_PLLINSP= 0xcd64,	/*!< PLL INSELP - PLL direct bandwidth control mode only with pll_bandsel set to 1 */
	TFA9873_BF_PLLINSR= 0xcdb3,	/*!< PLL INSELR - PLL direct bandwidth control mode only with pll_bandsel set to 1 */
	TFA9873_BF_PLLBDSEL= 0xcdf0,	/*!< PLL bandwidth selection control, USE WITH CAUTION	*/
	TFA9873_BF_PLLNDEC= 0xce09,	/*!< PLL NDEC in direct control mode only, use_direct_pll_ctrl set to 1 */
	TFA9873_BF_PLLMDECM= 0xcea0,	/*!< MSB of PLL MDEC in direct control mode only, use_direct_pll_ctrl set to 1 */
	TFA9873_BF_PLLBP = 0xceb0,	/*!< PLL bypass control during functional mode			*/
	TFA9873_BF_PLLDI = 0xcec0,	/*!< PLL directi control in direct control mode only, use_direct_pll_ctrl set to 1 */
	TFA9873_BF_PLLDO = 0xced0,	/*!< PLL directo control in direct control mode only, use_direct_pll_ctrl set to 1 */
	TFA9873_BF_PLLCLKSTB= 0xcee0,	/*!< PLL FRM clock stable control in direct control mode only, use_direct_pll_ctrl set to 1 */
	TFA9873_BF_PLLFRM= 0xcef0,	/*!< PLL free running mode control in functional mode	*/
	TFA9873_BF_PLLMDECL= 0xcf0f,	/*!< Bits 15 to 0 of PLL MDEC in direct control mode, use_direct_pll_ctrl set to 1 */
	TFA9873_BF_PLLPDEC= 0xd006,	/*!< PLL PDEC in direct control mode only, use_direct_pll_ctrl set to 1 */
	TFA9873_BF_PLLDCTRL= 0xd070,	/*!< Enabled PLL direct control mode, overrules the PLL LUT with I2C register values */
	TFA9873_BF_PLLLIMOFF= 0xd090,	/*!< PLL up limiter control in PLL direct bandwidth control mode, pll_bandsel set to 1 */
	TFA9873_BF_PLLSTRTM= 0xd0a2,	/*!< PLL startup time selection control				    */
	TFA9873_BF_SWPROFIL= 0xe00f,	/*!< Software profile data				                 */
	TFA9873_BF_SWVSTEP= 0xe10f,	/*!< Software vstep information				            */
	TFA9873_BF_MTPOTC= 0xf000,	/*!< Calibration schedule				                  */
	TFA9873_BF_MTPEX = 0xf010,	/*!< Calibration Ron executed				              */
	TFA9873_BF_DCMCCAPI= 0xf020,	/*!< Calibration current limit DCDC				        */
	TFA9873_BF_DCMCCSB= 0xf030,	/*!< Sign bit for delta calibration current limit DCDC	*/
	TFA9873_BF_USERDEF= 0xf042,	/*!< Calibration delta current limit DCDC				  */
	TFA9873_BF_CUSTINFO= 0xf078,	/*!< Reserved space for allowing customer to store speaker information */
	TFA9873_BF_R25C	= 0xf50f,	/*!< Ron resistance of speaker coil			          */
};

enum tfa9873_irq {
	tfa9873_irq_stvdds = 0,
	tfa9873_irq_stbstoc = 1,
	tfa9873_irq_stotds = 2,
	tfa9873_irq_stocpr = 3,
	tfa9873_irq_stuvds = 4,
	tfa9873_irq_stmanalarm = 5,
	tfa9873_irq_sttdmer = 6,
	tfa9873_irq_stnoclk = 7,
	tfa9873_irq_max = 8,
	tfa9873_irq_all = -1 /* all irqs */};

#endif

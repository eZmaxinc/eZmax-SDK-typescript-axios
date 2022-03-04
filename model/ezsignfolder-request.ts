/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.7
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { FieldEEzsignfolderSendreminderfrequency } from './field-eezsignfolder-sendreminderfrequency';

/**
 * An Ezsignfolder Object
 * @export
 * @interface EzsignfolderRequest
 */
export interface EzsignfolderRequest {
    /**
     * The unique ID of the Ezsignfolder
     * @type {number}
     * @memberof EzsignfolderRequest
     */
    'pkiEzsignfolderID'?: number;
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzsignfolderRequest
     */
    'fkiEzsignfoldertypeID': number;
    /**
     * The unique ID of the Ezsigntsarequirement.  Determine if a Time Stamping Authority should add a timestamp on each of the signature. Valid values:  |Value|Description| |-|-| |1|No. TSA Timestamping will requested. This will make all signatures a lot faster since no round-trip to the TSA server will be required. Timestamping will be made using eZsign server\'s time.| |2|Best effort. Timestamping from a Time Stamping Authority will be requested but is not mandatory. In the very improbable case it cannot be completed, the timestamping will be made using eZsign server\'s time. **Additional fee applies**| |3|Mandatory. Timestamping from a Time Stamping Authority will be requested and is mandatory. In the very improbable case it cannot be completed, the signature will fail and the user will be asked to retry. **Additional fee applies**|
     * @type {number}
     * @memberof EzsignfolderRequest
     */
    'fkiEzsigntsarequirementID': number;
    /**
     * The description of the Ezsignfolder
     * @type {string}
     * @memberof EzsignfolderRequest
     */
    'sEzsignfolderDescription': string;
    /**
     * Note about the Ezsignfolder
     * @type {string}
     * @memberof EzsignfolderRequest
     */
    'tEzsignfolderNote': string;
    /**
     * 
     * @type {FieldEEzsignfolderSendreminderfrequency}
     * @memberof EzsignfolderRequest
     */
    'eEzsignfolderSendreminderfrequency': FieldEEzsignfolderSendreminderfrequency;
}


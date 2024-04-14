/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
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
    /*'pkiEzsignfolderID'?: number;*/
    'pkiEzsignfolderID'?: number;
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzsignfolderRequest
     */
    /*'fkiEzsignfoldertypeID': number;*/
    'fkiEzsignfoldertypeID': number;
    /**
     * The unique ID of the Ezsigntsarequirement.  Determine if a Time Stamping Authority should add a timestamp on each of the signature. Valid values:  |Value|Description| |-|-| |1|No. TSA Timestamping will requested. This will make all signatures a lot faster since no round-trip to the TSA server will be required. Timestamping will be made using eZsign server\'s time.| |2|Best effort. Timestamping from a Time Stamping Authority will be requested but is not mandatory. In the very improbable case it cannot be completed, the timestamping will be made using eZsign server\'s time. **Additional fee applies**| |3|Mandatory. Timestamping from a Time Stamping Authority will be requested and is mandatory. In the very improbable case it cannot be completed, the signature will fail and the user will be asked to retry. **Additional fee applies**|
     * @type {number}
     * @memberof EzsignfolderRequest
     */
    /*'fkiEzsigntsarequirementID'?: number;*/
    'fkiEzsigntsarequirementID'?: number;
    /**
     * The description of the Ezsignfolder
     * @type {string}
     * @memberof EzsignfolderRequest
     */
    /*'sEzsignfolderDescription': string;*/
    'sEzsignfolderDescription': string;
    /**
     * Note about the Ezsignfolder
     * @type {string}
     * @memberof EzsignfolderRequest
     */
    /*'tEzsignfolderNote'?: string;*/
    'tEzsignfolderNote'?: string;
    /**
     * 
     * @type {FieldEEzsignfolderSendreminderfrequency}
     * @memberof EzsignfolderRequest
     */
    /*'eEzsignfolderSendreminderfrequency': FieldEEzsignfolderSendreminderfrequency;*/
    'eEzsignfolderSendreminderfrequency': FieldEEzsignfolderSendreminderfrequency;
    /**
     * This field can be used to store an External ID from the client\'s system.  Anything can be stored in this field, it will never be evaluated by the eZmax system and will be returned AS-IS.  To store multiple values, consider using a JSON formatted structure, a URL encoded string, a CSV or any other custom format. 
     * @type {string}
     * @memberof EzsignfolderRequest
     */
    /*'sEzsignfolderExternalid'?: string;*/
    'sEzsignfolderExternalid'?: string;
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignfolderRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderRequest
 */
export class DataObjectEzsignfolderRequest {
   pkiEzsignfolderID?:number = undefined
   fkiEzsignfoldertypeID:number = 0
   fkiEzsigntsarequirementID?:number = undefined
   sEzsignfolderDescription:string = ''
   tEzsignfolderNote?:string = undefined
   eEzsignfolderSendreminderfrequency:FieldEEzsignfolderSendreminderfrequency = 'None'
   sEzsignfolderExternalid?:string = undefined
}

/**
 * @export 
 * A EzsignfolderRequest Validation Object
 * @class ValidationObjectEzsignfolderRequest
 */
export class ValidationObjectEzsignfolderRequest {
   pkiEzsignfolderID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsignfoldertypeID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: true
   }
   fkiEzsigntsarequirementID = {
      type: 'integer',
      minimum: 1,
      maximum: 3,
      required: false
   }
   sEzsignfolderDescription = {
      type: 'string',
      required: true
   }
   tEzsignfolderNote = {
      type: 'string',
      required: false
   }
   eEzsignfolderSendreminderfrequency = {
      type: 'enum',
      allowableValues: ['None','Daily','Weekly'],
      required: true
   }
   sEzsignfolderExternalid = {
      type: 'string',
      pattern: '/^.{0,128}$/',
      required: false
   }
} 



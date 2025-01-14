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
import { EzsignfolderRequestV3 } from './ezsignfolder-request-v3';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignfolderDocumentdependency } from './field-eezsignfolder-documentdependency';

/**
 * @type EzsignfolderRequestCompoundV3
 * An Ezsignfolder Object and children to create a complete structure
 * @export
 */
/*export type EzsignfolderRequestCompoundV3 = EzsignfolderRequestV3;*/
export interface EzsignfolderRequestCompoundV3 {
    /**
     * The unique ID of the Ezsignfolder
     * @type {number}
     * @memberof EzsignfolderRequestCompoundV3
     */
    pkiEzsignfolderID?:number 
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzsignfolderRequestCompoundV3
     */
    fkiEzsignfoldertypeID:number 
    /**
     * The unique ID of the Timezone
     * @type {number}
     * @memberof EzsignfolderRequestCompoundV3
     */
    fkiTimezoneID?:number 
    /**
     * The unique ID of the Ezsigntsarequirement.  Determine if a Time Stamping Authority should add a timestamp on each of the signature. Valid values:  |Value|Description| |-|-| |1|No. TSA Timestamping will requested. This will make all signatures a lot faster since no round-trip to the TSA server will be required. Timestamping will be made using eZsign server\'s time.| |2|Best effort. Timestamping from a Time Stamping Authority will be requested but is not mandatory. In the very improbable case it cannot be completed, the timestamping will be made using eZsign server\'s time. **Additional fee applies**| |3|Mandatory. Timestamping from a Time Stamping Authority will be requested and is mandatory. In the very improbable case it cannot be completed, the signature will fail and the user will be asked to retry. **Additional fee applies**|
     * @type {number}
     * @memberof EzsignfolderRequestCompoundV3
     */
    fkiEzsigntsarequirementID?:number 
    /**
     * 
     * @type {FieldEEzsignfolderDocumentdependency}
     * @memberof EzsignfolderRequestCompoundV3
     */
    eEzsignfolderDocumentdependency?:FieldEEzsignfolderDocumentdependency 
    /**
     * The description of the Ezsignfolder
     * @type {string}
     * @memberof EzsignfolderRequestCompoundV3
     */
    sEzsignfolderDescription:string 
    /**
     * Note about the Ezsignfolder
     * @type {string}
     * @memberof EzsignfolderRequestCompoundV3
     */
    tEzsignfolderNote?:string 
    /**
     * A custom text message that will be added to the email sent.
     * @type {string}
     * @memberof EzsignfolderRequestCompoundV3
     */
    tEzsignfolderMessage?:string 
    /**
     * The number of days before the the first reminder sending
     * @type {number}
     * @memberof EzsignfolderRequestCompoundV3
     */
    iEzsignfolderSendreminderfirstdays:number 
    /**
     * The number of days after the first reminder sending
     * @type {number}
     * @memberof EzsignfolderRequestCompoundV3
     */
    iEzsignfolderSendreminderotherdays:number 
    /**
     * This field can be used to store an External ID from the client\'s system.  Anything can be stored in this field, it will never be evaluated by the eZmax system and will be returned AS-IS.  To store multiple values, consider using a JSON formatted structure, a URL encoded string, a CSV or any other custom format. 
     * @type {string}
     * @memberof EzsignfolderRequestCompoundV3
     */
    sEzsignfolderExternalid?:string 
}



/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignfolderRequestCompoundV3 Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderRequestCompoundV3
 */
export class DataObjectEzsignfolderRequestCompoundV3 {
    pkiEzsignfolderID?:number = undefined
    fkiEzsignfoldertypeID:number = 0
    fkiTimezoneID?:number = undefined
    fkiEzsigntsarequirementID?:number = undefined
    eEzsignfolderDocumentdependency?:FieldEEzsignfolderDocumentdependency = undefined
    sEzsignfolderDescription:string = ''
    tEzsignfolderNote?:string = undefined
    tEzsignfolderMessage?:string = undefined
    iEzsignfolderSendreminderfirstdays:number = 0
    iEzsignfolderSendreminderotherdays:number = 0
    sEzsignfolderExternalid?:string = undefined
}

/**
 * @export 
 * A EzsignfolderRequestCompoundV3 Validation Object
 * @class ValidationObjectEzsignfolderRequestCompoundV3
 */
export class ValidationObjectEzsignfolderRequestCompoundV3 {
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
   fkiTimezoneID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsigntsarequirementID = {
      type: 'integer',
      minimum: 1,
      maximum: 3,
      required: false
   }
   eEzsignfolderDocumentdependency = {
      type: 'enum',
      allowableValues: ['All','EzsignsignerOnly'],
      required: false
   }
   sEzsignfolderDescription = {
      type: 'string',
      pattern: /^.{0,75}$/,
      required: true
   }
   tEzsignfolderNote = {
      type: 'string',
      required: false
   }
   tEzsignfolderMessage = {
      type: 'string',
      required: false
   }
   iEzsignfolderSendreminderfirstdays = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   iEzsignfolderSendreminderotherdays = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   sEzsignfolderExternalid = {
      type: 'string',
      pattern: /^.{0,128}$/,
      required: false
   }
} 



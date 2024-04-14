/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigndocumentlogType } from './field-eezsigndocumentlog-type';

/**
 * An Ezsigndocumentlog Object
 * @export
 * @interface EzsigndocumentlogResponse
 */
export interface EzsigndocumentlogResponse {
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof EzsigndocumentlogResponse
     */
    /*'fkiUserID'?: number;*/
    'fkiUserID'?: number;
    /**
     * The unique ID of the Ezsignsigner
     * @type {number}
     * @memberof EzsigndocumentlogResponse
     */
    /*'fkiEzsignsignerID'?: number;*/
    'fkiEzsignsignerID'?: number;
    /**
     * The date and time at which the event was logged
     * @type {string}
     * @memberof EzsigndocumentlogResponse
     */
    /*'dtEzsigndocumentlogDatetime': string;*/
    'dtEzsigndocumentlogDatetime': string;
    /**
     * 
     * @type {FieldEEzsigndocumentlogType}
     * @memberof EzsigndocumentlogResponse
     */
    /*'eEzsigndocumentlogType': FieldEEzsigndocumentlogType;*/
    'eEzsigndocumentlogType': FieldEEzsigndocumentlogType;
    /**
     * The detail of the Ezsigndocumentlog
     * @type {string}
     * @memberof EzsigndocumentlogResponse
     */
    /*'sEzsigndocumentlogDetail': string;*/
    'sEzsigndocumentlogDetail': string;
    /**
     * The last name of the User or Ezsignsigner
     * @type {string}
     * @memberof EzsigndocumentlogResponse
     */
    /*'sEzsigndocumentlogLastname': string;*/
    'sEzsigndocumentlogLastname': string;
    /**
     * The first name of the User or Ezsignsigner
     * @type {string}
     * @memberof EzsigndocumentlogResponse
     */
    /*'sEzsigndocumentlogFirstname': string;*/
    'sEzsigndocumentlogFirstname': string;
    /**
     * Represent an IP address.
     * @type {string}
     * @memberof EzsigndocumentlogResponse
     */
    /*'sEzsigndocumentlogIP': string;*/
    'sEzsigndocumentlogIP': string;
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigndocumentlogResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentlogResponse
 */
export class DataObjectEzsigndocumentlogResponse {
   fkiUserID?:number = undefined
   fkiEzsignsignerID?:number = undefined
   dtEzsigndocumentlogDatetime:string = ''
   eEzsigndocumentlogType:FieldEEzsigndocumentlogType = 'Clone'
   sEzsigndocumentlogDetail:string = ''
   sEzsigndocumentlogLastname:string = ''
   sEzsigndocumentlogFirstname:string = ''
   sEzsigndocumentlogIP:string = ''
}

/**
 * @export 
 * A EzsigndocumentlogResponse Validation Object
 * @class ValidationObjectEzsigndocumentlogResponse
 */
export class ValidationObjectEzsigndocumentlogResponse {
   fkiUserID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsignsignerID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   dtEzsigndocumentlogDatetime = {
      type: 'string',
      required: true
   }
   eEzsigndocumentlogType = {
      type: 'enum',
      allowableValues: ['Clone','Login','Sendcode','Badcode','Goodcode','Badresponse','Goodresponse','Authentication','Createpage','Download','Send','Sign','Upload','View','Completion','Changelimitdate','Unsign','ImportFromInstanet','SendEmail','FormCompletion','SignatureAttachmentAdd','SignatureAttachmentValidation','SignatureAttachmentRefused','SignatureAttachmentDeleted','DeclinedToSign','DelayedSendEmail','AnnotationAdded','Flatten','RegeneratePage','RegeneratePageForm','Reassign'],
      required: true
   }
   sEzsigndocumentlogDetail = {
      type: 'string',
      required: true
   }
   sEzsigndocumentlogLastname = {
      type: 'string',
      required: true
   }
   sEzsigndocumentlogFirstname = {
      type: 'string',
      required: true
   }
   sEzsigndocumentlogIP = {
      type: 'string',
      required: true
   }
} 



/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { FieldEAttachmentlogType } from './field-eattachmentlog-type';

/**
 * An Attachmentlog Object
 * @export
 * @interface AttachmentlogResponse
 */
export interface AttachmentlogResponse {
    /**
     * The unique ID of the Attachment.
     * @type {number}
     * @memberof AttachmentlogResponse
     */
    /*'fkiAttachmentID': number;*/
    'fkiAttachmentID': number;
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof AttachmentlogResponse
     */
    /*'fkiUserID': number;*/
    'fkiUserID': number;
    /**
     * The created date
     * @type {string}
     * @memberof AttachmentlogResponse
     */
    /*'dtAttachmentlogDatetime': string;*/
    'dtAttachmentlogDatetime': string;
    /**
     * 
     * @type {FieldEAttachmentlogType}
     * @memberof AttachmentlogResponse
     */
    /*'eAttachmentlogType': FieldEAttachmentlogType;*/
    'eAttachmentlogType': FieldEAttachmentlogType;
    /**
     * The additionnal detail
     * @type {string}
     * @memberof AttachmentlogResponse
     */
    /*'sAttachmentlogDetail'?: string;*/
    'sAttachmentlogDetail'?: string;
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A AttachmentlogResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectAttachmentlogResponse
 */
export class DataObjectAttachmentlogResponse {
   fkiAttachmentID:number = 0
   fkiUserID:number = 0
   dtAttachmentlogDatetime:string = ''
   eAttachmentlogType:FieldEAttachmentlogType = 'AutoValidation'
   sAttachmentlogDetail?:string = undefined
}

/**
 * @export 
 * A AttachmentlogResponse Validation Object
 * @class ValidationObjectAttachmentlogResponse
 */
export class ValidationObjectAttachmentlogResponse {
   fkiAttachmentID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiUserID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   dtAttachmentlogDatetime = {
      type: 'string',
      pattern: /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1]) ([01]?[0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])$/,
      required: true
   }
   eAttachmentlogType = {
      type: 'enum',
      allowableValues: ['AutoValidation','CopyFrom','CopyTo','CopyToEzsign','CreateByEzsign','Download','Deleted','Destroyed','Email','EmailCC','EmailCCI','Fax','ImportedFromExternalSystem','ImportedFromEZA','ImportedFromFaltour','ImportedFromLonewolf','ImportedFromProspects','Move','OpenFromEmail','Purged','Reject','Rename','Restore','Scanned','SendToGED','UnvalidatedBy','Upload','ValidatedBy','VetinfoUpload'],
      required: true
   }
   sAttachmentlogDetail = {
      type: 'string',
      pattern: /^.{0,75}$/,
      required: false
   }
} 



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



/**
 * An Ezsignsignatureattachment Object
 * @export
 * @interface EzsignsignatureattachmentResponse
 */
export interface EzsignsignatureattachmentResponse {
    /**
     * The unique ID of the Ezsignsignatureattachment
     * @type {number}
     * @memberof EzsignsignatureattachmentResponse
     */
    /*'pkiEzsignsignatureattachmentID': number;*/
    'pkiEzsignsignatureattachmentID': number;
    /**
     * The unique ID of the Ezsignsignature
     * @type {number}
     * @memberof EzsignsignatureattachmentResponse
     */
    /*'fkiEzsignsignatureID': number;*/
    'fkiEzsignsignatureID': number;
    /**
     * The md5 of the Ezsignsignatureattachment
     * @type {string}
     * @memberof EzsignsignatureattachmentResponse
     */
    /*'binEzsignsignatureattachmentMD5': string;*/
    'binEzsignsignatureattachmentMD5': string;
    /**
     * The name of the Ezsignsignatureattachment
     * @type {string}
     * @memberof EzsignsignatureattachmentResponse
     */
    /*'sEzsignsignatureattachmentName': string;*/
    'sEzsignsignatureattachmentName': string;
    /**
     * The Url to the requested document.  Url will expire after 3 hours.
     * @type {string}
     * @memberof EzsignsignatureattachmentResponse
     */
    /*'sDownloadUrl': string;*/
    'sDownloadUrl': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignsignatureattachmentResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignatureattachmentResponse
 */
export class DataObjectEzsignsignatureattachmentResponse {
   pkiEzsignsignatureattachmentID:number = 0
   fkiEzsignsignatureID:number = 0
   binEzsignsignatureattachmentMD5:string = ''
   sEzsignsignatureattachmentName:string = ''
   sDownloadUrl:string = ''
}

/**
 * @export 
 * A EzsignsignatureattachmentResponse Validation Object
 * @class ValidationObjectEzsignsignatureattachmentResponse
 */
export class ValidationObjectEzsignsignatureattachmentResponse {
   pkiEzsignsignatureattachmentID = {
      type: 'integer',
      minimum: 1,
      maximum: 16777215,
      required: true
   }
   fkiEzsignsignatureID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   binEzsignsignatureattachmentMD5 = {
      type: 'string',
      required: true
   }
   sEzsignsignatureattachmentName = {
      type: 'string',
      pattern: /^.{0,75}$/,
      required: true
   }
   sDownloadUrl = {
      type: 'string',
      required: true
   }
} 



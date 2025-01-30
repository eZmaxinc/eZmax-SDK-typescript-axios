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
 * Payload for GET /1/object/ezsigndocument/{pkiEzsigndocument}/getDownloadUrl
 * @export
 * @interface EzsigndocumentGetDownloadUrlV1ResponseMPayload
 */
export interface EzsigndocumentGetDownloadUrlV1ResponseMPayload {
    /**
     * The Url to the requested document.  Url will expire after 5 minutes.
     * @type {string}
     * @memberof EzsigndocumentGetDownloadUrlV1ResponseMPayload
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
 * A EzsigndocumentGetDownloadUrlV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentGetDownloadUrlV1ResponseMPayload
 */
export class DataObjectEzsigndocumentGetDownloadUrlV1ResponseMPayload {
   sDownloadUrl:string = ''
}

/**
 * @export 
 * A EzsigndocumentGetDownloadUrlV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsigndocumentGetDownloadUrlV1ResponseMPayload
 */
export class ValidationObjectEzsigndocumentGetDownloadUrlV1ResponseMPayload {
   sDownloadUrl = {
      type: 'string',
      required: true
   }
} 



/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.14
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

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
    'sDownloadUrl': string;
}
/**
 * A EzsigndocumentGetDownloadUrlV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigndocumentGetDownloadUrlV1ResponseMPayload
 */
export class DefaultObjectEzsigndocumentGetDownloadUrlV1ResponseMPayload extends DefaultObject {
   sDownloadUrl:string = ''
}



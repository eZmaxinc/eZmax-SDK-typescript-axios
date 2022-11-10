/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.16
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface CommonResponseErrorSTemporaryFileUrlAllOf
 */
export interface CommonResponseErrorSTemporaryFileUrlAllOf {
    /**
     * The Temporary File Url of the document that was uploaded. That url can be reused instead of uploading the file again.
     * @type {string}
     * @memberof CommonResponseErrorSTemporaryFileUrlAllOf
     */
    'sTemporaryFileUrl'?: string;
}
/**
 * A CommonResponseErrorSTemporaryFileUrlAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectCommonResponseErrorSTemporaryFileUrlAllOf
 */
export class DefaultObjectCommonResponseErrorSTemporaryFileUrlAllOf extends DefaultObject {
   sTemporaryFileUrl?:string = undefined
}



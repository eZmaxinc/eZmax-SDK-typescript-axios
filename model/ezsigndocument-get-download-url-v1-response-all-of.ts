/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.12
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigndocumentGetDownloadUrlV1ResponseMPayload } from './ezsigndocument-get-download-url-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsigndocumentGetDownloadUrlV1ResponseAllOf
 */
export interface EzsigndocumentGetDownloadUrlV1ResponseAllOf {
    /**
     * 
     * @type {EzsigndocumentGetDownloadUrlV1ResponseMPayload}
     * @memberof EzsigndocumentGetDownloadUrlV1ResponseAllOf
     */
    'mPayload': EzsigndocumentGetDownloadUrlV1ResponseMPayload;
}
/**
 * A EzsigndocumentGetDownloadUrlV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigndocumentGetDownloadUrlV1ResponseAllOf
 */
export class DefaultObjectEzsigndocumentGetDownloadUrlV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsigndocumentGetDownloadUrlV1ResponseMPayload> = {}
}



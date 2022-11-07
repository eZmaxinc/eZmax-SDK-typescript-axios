/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.15
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigndocumentGetEzsignpagesV1ResponseMPayload } from './ezsigndocument-get-ezsignpages-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsigndocumentGetEzsignpagesV1ResponseAllOf
 */
export interface EzsigndocumentGetEzsignpagesV1ResponseAllOf {
    /**
     * 
     * @type {EzsigndocumentGetEzsignpagesV1ResponseMPayload}
     * @memberof EzsigndocumentGetEzsignpagesV1ResponseAllOf
     */
    'mPayload': EzsigndocumentGetEzsignpagesV1ResponseMPayload;
}
/**
 * A EzsigndocumentGetEzsignpagesV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigndocumentGetEzsignpagesV1ResponseAllOf
 */
export class DefaultObjectEzsigndocumentGetEzsignpagesV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsigndocumentGetEzsignpagesV1ResponseMPayload> = {}
}



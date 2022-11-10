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


// May contain unused imports in some cases
// @ts-ignore
import { EzsignsignatureGetObjectV1ResponseMPayload } from './ezsignsignature-get-object-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsignsignatureGetObjectV1ResponseAllOf
 */
export interface EzsignsignatureGetObjectV1ResponseAllOf {
    /**
     * 
     * @type {EzsignsignatureGetObjectV1ResponseMPayload}
     * @memberof EzsignsignatureGetObjectV1ResponseAllOf
     */
    'mPayload': EzsignsignatureGetObjectV1ResponseMPayload;
}
/**
 * A EzsignsignatureGetObjectV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignsignatureGetObjectV1ResponseAllOf
 */
export class DefaultObjectEzsignsignatureGetObjectV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsignsignatureGetObjectV1ResponseMPayload> = {}
}



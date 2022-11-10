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
import { EzsignsignatureCreateObjectV2ResponseMPayload } from './ezsignsignature-create-object-v2-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsignsignatureCreateObjectV2ResponseAllOf
 */
export interface EzsignsignatureCreateObjectV2ResponseAllOf {
    /**
     * 
     * @type {EzsignsignatureCreateObjectV2ResponseMPayload}
     * @memberof EzsignsignatureCreateObjectV2ResponseAllOf
     */
    'mPayload': EzsignsignatureCreateObjectV2ResponseMPayload;
}
/**
 * A EzsignsignatureCreateObjectV2ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignsignatureCreateObjectV2ResponseAllOf
 */
export class DefaultObjectEzsignsignatureCreateObjectV2ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsignsignatureCreateObjectV2ResponseMPayload> = {}
}



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


// May contain unused imports in some cases
// @ts-ignore
import { ApikeyCreateObjectV2ResponseMPayload } from './apikey-create-object-v2-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface ApikeyCreateObjectV2ResponseAllOf
 */
export interface ApikeyCreateObjectV2ResponseAllOf {
    /**
     * 
     * @type {ApikeyCreateObjectV2ResponseMPayload}
     * @memberof ApikeyCreateObjectV2ResponseAllOf
     */
    'mPayload': ApikeyCreateObjectV2ResponseMPayload;
}
/**
 * A ApikeyCreateObjectV2ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectApikeyCreateObjectV2ResponseAllOf
 */
export class DefaultObjectApikeyCreateObjectV2ResponseAllOf extends DefaultObject {
   mPayload:Partial<ApikeyCreateObjectV2ResponseMPayload> = {}
}



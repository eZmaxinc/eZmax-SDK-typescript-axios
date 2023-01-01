/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { ApikeyCreateObjectV1ResponseMPayload } from './apikey-create-object-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface ApikeyCreateObjectV1ResponseAllOf
 */
export interface ApikeyCreateObjectV1ResponseAllOf {
    /**
     * 
     * @type {ApikeyCreateObjectV1ResponseMPayload}
     * @memberof ApikeyCreateObjectV1ResponseAllOf
     */
    'mPayload': ApikeyCreateObjectV1ResponseMPayload;
}
/**
 * A ApikeyCreateObjectV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectApikeyCreateObjectV1ResponseAllOf
 */
export class DefaultObjectApikeyCreateObjectV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<ApikeyCreateObjectV1ResponseMPayload> = {}
}



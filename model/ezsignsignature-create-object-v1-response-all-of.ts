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
import { EzsignsignatureCreateObjectV1ResponseMPayload } from './ezsignsignature-create-object-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsignsignatureCreateObjectV1ResponseAllOf
 */
export interface EzsignsignatureCreateObjectV1ResponseAllOf {
    /**
     * 
     * @type {EzsignsignatureCreateObjectV1ResponseMPayload}
     * @memberof EzsignsignatureCreateObjectV1ResponseAllOf
     */
    'mPayload': EzsignsignatureCreateObjectV1ResponseMPayload;
}
/**
 * A EzsignsignatureCreateObjectV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignsignatureCreateObjectV1ResponseAllOf
 */
export class DefaultObjectEzsignsignatureCreateObjectV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsignsignatureCreateObjectV1ResponseMPayload> = {}
}



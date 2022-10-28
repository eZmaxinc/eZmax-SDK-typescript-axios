/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.13
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatesignatureCreateObjectV1ResponseMPayload } from './ezsigntemplatesignature-create-object-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsigntemplatesignatureCreateObjectV1ResponseAllOf
 */
export interface EzsigntemplatesignatureCreateObjectV1ResponseAllOf {
    /**
     * 
     * @type {EzsigntemplatesignatureCreateObjectV1ResponseMPayload}
     * @memberof EzsigntemplatesignatureCreateObjectV1ResponseAllOf
     */
    'mPayload': EzsigntemplatesignatureCreateObjectV1ResponseMPayload;
}
/**
 * A EzsigntemplatesignatureCreateObjectV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatesignatureCreateObjectV1ResponseAllOf
 */
export class DefaultObjectEzsigntemplatesignatureCreateObjectV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsigntemplatesignatureCreateObjectV1ResponseMPayload> = {}
}



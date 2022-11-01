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
import { BrandingCreateObjectV1ResponseMPayload } from './branding-create-object-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface BrandingCreateObjectV1ResponseAllOf
 */
export interface BrandingCreateObjectV1ResponseAllOf {
    /**
     * 
     * @type {BrandingCreateObjectV1ResponseMPayload}
     * @memberof BrandingCreateObjectV1ResponseAllOf
     */
    'mPayload': BrandingCreateObjectV1ResponseMPayload;
}
/**
 * A BrandingCreateObjectV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectBrandingCreateObjectV1ResponseAllOf
 */
export class DefaultObjectBrandingCreateObjectV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<BrandingCreateObjectV1ResponseMPayload> = {}
}



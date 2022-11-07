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
import { BrandingRequestCompound } from './branding-request-compound';

import { DefaultObject } from '../base'

/**
 * Request for POST /1/object/branding
 * @export
 * @interface BrandingCreateObjectV1Request
 */
export interface BrandingCreateObjectV1Request {
    /**
     * 
     * @type {Array<BrandingRequestCompound>}
     * @memberof BrandingCreateObjectV1Request
     */
    'a_objBranding': Array<BrandingRequestCompound>;
}
/**
 * A BrandingCreateObjectV1Request Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectBrandingCreateObjectV1Request
 */
export class DefaultObjectBrandingCreateObjectV1Request extends DefaultObject {
   a_objBranding:Array<BrandingRequestCompound> = []
}



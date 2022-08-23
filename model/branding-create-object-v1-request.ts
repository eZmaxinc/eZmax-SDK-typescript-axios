/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.10
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { BrandingRequestCompound } from './branding-request-compound';

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


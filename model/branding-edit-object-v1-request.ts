/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { BrandingRequestCompound } from './branding-request-compound';

/**
 * Request for PUT /1/object/branding/{pkiBrandingID}
 * @export
 * @interface BrandingEditObjectV1Request
 */
export interface BrandingEditObjectV1Request {
    /**
     * 
     * @type {BrandingRequestCompound}
     * @memberof BrandingEditObjectV1Request
     */
    'objBranding': BrandingRequestCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectBrandingRequestCompound } from './'
// @ts-ignore
import { ValidationObjectBrandingRequestCompound } from './'

/**
 * @export 
 * A BrandingEditObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectBrandingEditObjectV1Request
 */
export class DataObjectBrandingEditObjectV1Request {
   objBranding:BrandingRequestCompound = new DataObjectBrandingRequestCompound()
}

/**
 * @export 
 * A BrandingEditObjectV1Request Validation Object
 * @class ValidationObjectBrandingEditObjectV1Request
 */
export class ValidationObjectBrandingEditObjectV1Request {
   objBranding = new ValidationObjectBrandingRequestCompound()
} 



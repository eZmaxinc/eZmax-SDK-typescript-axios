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
import { EzsigntemplatepackagesignermembershipCreateObjectV1ResponseMPayload } from './ezsigntemplatepackagesignermembership-create-object-v1-response-mpayload';

/**
 * 
 * @export
 * @interface EzsigntemplatepackagesignermembershipCreateObjectV1ResponseAllOf
 */
export interface EzsigntemplatepackagesignermembershipCreateObjectV1ResponseAllOf {
    /**
     * 
     * @type {EzsigntemplatepackagesignermembershipCreateObjectV1ResponseMPayload}
     * @memberof EzsigntemplatepackagesignermembershipCreateObjectV1ResponseAllOf
     */
    'mPayload': EzsigntemplatepackagesignermembershipCreateObjectV1ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplatepackagesignermembershipCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatepackagesignermembershipCreateObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntemplatepackagesignermembershipCreateObjectV1ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackagesignermembershipCreateObjectV1ResponseAllOf
 */
export class DataObjectEzsigntemplatepackagesignermembershipCreateObjectV1ResponseAllOf {
   mPayload:EzsigntemplatepackagesignermembershipCreateObjectV1ResponseMPayload = new DataObjectEzsigntemplatepackagesignermembershipCreateObjectV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigntemplatepackagesignermembershipCreateObjectV1ResponseAllOf Validation Object
 * @class ValidationObjectEzsigntemplatepackagesignermembershipCreateObjectV1ResponseAllOf
 */
export class ValidationObjectEzsigntemplatepackagesignermembershipCreateObjectV1ResponseAllOf {
   mPayload = new ValidationObjectEzsigntemplatepackagesignermembershipCreateObjectV1ResponseMPayload()
} 



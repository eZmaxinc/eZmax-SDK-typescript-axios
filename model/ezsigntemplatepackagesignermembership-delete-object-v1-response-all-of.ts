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
import { EzsigntemplatepackagesignermembershipDeleteObjectV1ResponseMPayload } from './ezsigntemplatepackagesignermembership-delete-object-v1-response-mpayload';

/**
 * 
 * @export
 * @interface EzsigntemplatepackagesignermembershipDeleteObjectV1ResponseAllOf
 */
export interface EzsigntemplatepackagesignermembershipDeleteObjectV1ResponseAllOf {
    /**
     * 
     * @type {EzsigntemplatepackagesignermembershipDeleteObjectV1ResponseMPayload}
     * @memberof EzsigntemplatepackagesignermembershipDeleteObjectV1ResponseAllOf
     */
    'mPayload': EzsigntemplatepackagesignermembershipDeleteObjectV1ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplatepackagesignermembershipDeleteObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatepackagesignermembershipDeleteObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntemplatepackagesignermembershipDeleteObjectV1ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackagesignermembershipDeleteObjectV1ResponseAllOf
 */
export class DataObjectEzsigntemplatepackagesignermembershipDeleteObjectV1ResponseAllOf {
   mPayload:EzsigntemplatepackagesignermembershipDeleteObjectV1ResponseMPayload = new DataObjectEzsigntemplatepackagesignermembershipDeleteObjectV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigntemplatepackagesignermembershipDeleteObjectV1ResponseAllOf Validation Object
 * @class ValidationObjectEzsigntemplatepackagesignermembershipDeleteObjectV1ResponseAllOf
 */
export class ValidationObjectEzsigntemplatepackagesignermembershipDeleteObjectV1ResponseAllOf {
   mPayload = new ValidationObjectEzsigntemplatepackagesignermembershipDeleteObjectV1ResponseMPayload()
} 



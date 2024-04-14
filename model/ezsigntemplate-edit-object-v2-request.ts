/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateRequestCompoundV2 } from './ezsigntemplate-request-compound-v2';

/**
 * Request for PUT /2/object/ezsigntemplate/{pkiEzsigntemplateID}
 * @export
 * @interface EzsigntemplateEditObjectV2Request
 */
export interface EzsigntemplateEditObjectV2Request {
    /**
     * 
     * @type {EzsigntemplateRequestCompoundV2}
     * @memberof EzsigntemplateEditObjectV2Request
     */
    /*'objEzsigntemplate': EzsigntemplateRequestCompoundV2;*/
    'objEzsigntemplate': EzsigntemplateRequestCompoundV2;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplateRequestCompoundV2 } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplateRequestCompoundV2 } from './'

/**
 * @export 
 * A EzsigntemplateEditObjectV2Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateEditObjectV2Request
 */
export class DataObjectEzsigntemplateEditObjectV2Request {
   objEzsigntemplate:EzsigntemplateRequestCompoundV2 = new DataObjectEzsigntemplateRequestCompoundV2()
}

/**
 * @export 
 * A EzsigntemplateEditObjectV2Request Validation Object
 * @class ValidationObjectEzsigntemplateEditObjectV2Request
 */
export class ValidationObjectEzsigntemplateEditObjectV2Request {
   objEzsigntemplate = new ValidationObjectEzsigntemplateRequestCompoundV2()
} 



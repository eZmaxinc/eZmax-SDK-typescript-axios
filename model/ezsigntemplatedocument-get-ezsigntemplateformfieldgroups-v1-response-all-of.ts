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
import { EzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseMPayload } from './ezsigntemplatedocument-get-ezsigntemplateformfieldgroups-v1-response-mpayload';

/**
 * 
 * @export
 * @interface EzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseAllOf
 */
export interface EzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseAllOf {
    /**
     * 
     * @type {EzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseMPayload}
     * @memberof EzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseAllOf
     */
    'mPayload': EzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseAllOf
 */
export class DataObjectEzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseAllOf {
   mPayload:EzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseMPayload = new DataObjectEzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseAllOf Validation Object
 * @class ValidationObjectEzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseAllOf
 */
export class ValidationObjectEzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseAllOf {
   mPayload = new ValidationObjectEzsigntemplatedocumentGetEzsigntemplateformfieldgroupsV1ResponseMPayload()
} 



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



import { DefaultObject } from '../base'

/**
 * A Ezsigntemplateformfieldgroupsigner Object
 * @export
 * @interface EzsigntemplateformfieldgroupsignerRequest
 */
export interface EzsigntemplateformfieldgroupsignerRequest {
    /**
     * The unique ID of the Ezsigntemplateformfieldgroupsigner
     * @type {number}
     * @memberof EzsigntemplateformfieldgroupsignerRequest
     */
    'pkiEzsigntemplateformfieldgroupsignerID'?: number;
    /**
     * The unique ID of the Ezsigntemplatesigner
     * @type {number}
     * @memberof EzsigntemplateformfieldgroupsignerRequest
     */
    'fkiEzsigntemplatesignerID': number;
}
/**
 * A EzsigntemplateformfieldgroupsignerRequest Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplateformfieldgroupsignerRequest
 */
export class DefaultObjectEzsigntemplateformfieldgroupsignerRequest extends DefaultObject {
   pkiEzsigntemplateformfieldgroupsignerID?:number = undefined
   fkiEzsigntemplatesignerID:number = 0
}



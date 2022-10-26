/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.12
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateformfieldgroupsignerRequest } from './ezsigntemplateformfieldgroupsigner-request';

import { DefaultObject } from '../base'

/**
 * @type EzsigntemplateformfieldgroupsignerRequestCompound
 * An Ezsigntemplateformfieldgroupsigner Object and children to create a complete structure
 * @export
 */
export type EzsigntemplateformfieldgroupsignerRequestCompound = EzsigntemplateformfieldgroupsignerRequest;


/**
 * @export 
 * A EzsigntemplateformfieldgroupsignerRequestCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigntemplateformfieldgroupsignerRequestCompound
 */
export class DefaultObjectEzsigntemplateformfieldgroupsignerRequestCompound extends DefaultObject {
   pkiEzsigntemplateformfieldgroupsignerID?:number = undefined
   fkiEzsigntemplatesignerID:number = 0
}



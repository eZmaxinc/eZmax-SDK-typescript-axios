/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.16
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackagesignerRequest } from './ezsigntemplatepackagesigner-request';

import { DefaultObject } from '../base'

/**
 * @type EzsigntemplatepackagesignerRequestCompound
 * A Ezsigntemplatepackagesigner Object and children
 * @export
 */
export type EzsigntemplatepackagesignerRequestCompound = EzsigntemplatepackagesignerRequest;


/**
 * @export 
 * A EzsigntemplatepackagesignerRequestCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigntemplatepackagesignerRequestCompound
 */
export class DefaultObjectEzsigntemplatepackagesignerRequestCompound extends DefaultObject {
   pkiEzsigntemplatepackagesignerID?:number = undefined
   fkiEzsigntemplatepackageID:number = 0
   sEzsigntemplatepackagesignerDescription:string = ''
}



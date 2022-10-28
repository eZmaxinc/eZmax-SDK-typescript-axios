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


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackagesignerResponse } from './ezsigntemplatepackagesigner-response';

import { DefaultObject } from '../base'

/**
 * @type EzsigntemplatepackagesignerResponseCompound
 * A Ezsigntemplatepackagesigner Object
 * @export
 */
export type EzsigntemplatepackagesignerResponseCompound = EzsigntemplatepackagesignerResponse;


/**
 * @export 
 * A EzsigntemplatepackagesignerResponseCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigntemplatepackagesignerResponseCompound
 */
export class DefaultObjectEzsigntemplatepackagesignerResponseCompound extends DefaultObject {
   pkiEzsigntemplatepackagesignerID:number = 0
   fkiEzsigntemplatepackageID:number = 0
   sEzsigntemplatepackagesignerDescription:string = ''
}



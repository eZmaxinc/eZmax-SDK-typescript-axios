/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatesignerResponse } from './ezsigntemplatesigner-response';

import { DefaultObject } from '../base'

/**
 * @type EzsigntemplatesignerResponseCompound
 * A Ezsigntemplatesigner Object
 * @export
 */
export type EzsigntemplatesignerResponseCompound = EzsigntemplatesignerResponse;


/**
 * @export 
 * A EzsigntemplatesignerResponseCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigntemplatesignerResponseCompound
 */
export class DefaultObjectEzsigntemplatesignerResponseCompound extends DefaultObject {
   pkiEzsigntemplatesignerID:number = 0
   fkiEzsigntemplateID:number = 0
   sEzsigntemplatesignerDescription:string = ''
}



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
import { EzsigntemplatesignaturecustomdateResponse } from './ezsigntemplatesignaturecustomdate-response';

import { DefaultObject } from '../base'

/**
 * @type EzsigntemplatesignaturecustomdateResponseCompound
 * An Ezsigntemplatesignaturecustomdate Object and children to create a complete structure
 * @export
 */
export type EzsigntemplatesignaturecustomdateResponseCompound = EzsigntemplatesignaturecustomdateResponse;


/**
 * @export 
 * A EzsigntemplatesignaturecustomdateResponseCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigntemplatesignaturecustomdateResponseCompound
 */
export class DefaultObjectEzsigntemplatesignaturecustomdateResponseCompound extends DefaultObject {
   pkiEzsigntemplatesignaturecustomdateID:number = 0
   iEzsigntemplatesignaturecustomdateX:number = 0
   iEzsigntemplatesignaturecustomdateY:number = 0
   sEzsigntemplatesignaturecustomdateFormat:string = ''
}


